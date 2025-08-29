//! # Secure Password Manager
//!
//! A comprehensive password management application built in Rust that provides:
//! - Command-line interface for password operations
//! - Graphical user interface using egui
//! - Secure encryption using AES-256-GCM with Argon2 key derivation
//! - Web server for remote access
//! - Colored terminal output for better user experience
//!
//! ## Features
//!
//! - **Secure Storage**: Passwords are encrypted using AES-256-GCM
//! - **Strong Key Derivation**: Uses Argon2 to derive encryption keys from master password
//! - **Multiple Interfaces**: CLI, GUI, and web server modes
//! - **Password Management**: Add, retrieve, list, and delete password entries
//! - **User-Friendly**: Colored output and intuitive interfaces
//!
//! ## Security Notes
//!
//! - Master password is used to derive encryption key
//! - All passwords are stored encrypted on disk
//! - Uses random nonces for each encryption operation
//! - Salt should be randomly generated in production (currently hardcoded for demo)

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use aes_gcm::{Aes256Gcm, Key};
use aes_gcm::aead::{Aead, KeyInit};
use argon2::Argon2;
use std::fs;
use std::path::Path;
use rpassword::read_password;
use tokio;
use axum::{routing::{post, get}, Router};
use axum::body::{Body, to_bytes};
use std::sync::Arc;
use tokio::sync::Mutex;
use colored::*;

// ====================
// DATA STRUCTURES
// ====================

/// Represents a single password entry in the password manager
#[derive(Serialize, Deserialize, Clone)]
struct PasswordEntry {
    /// The name/identifier for this password entry (e.g., "gmail", "github")
    name: String,
    /// The username or email associated with this password
    username: String,
    /// The actual password (stored encrypted)
    password: String,
}

/// Command-line interface configuration using clap
#[derive(Parser)]
#[command(name = "password-manager")]
#[command(about = "A secure password manager with CLI, GUI, and web server modes")]
struct Cli {
    /// The subcommand to execute
    #[command(subcommand)]
    command: Option<Commands>,

    /// Launch the graphical user interface instead of CLI
    #[arg(long)]
    gui: bool,
}

/// Available CLI commands for password management
#[derive(Subcommand)]
enum Commands {
    /// Add a new password entry
    Add {
        /// Name identifier for the password entry
        name: String,
        /// Username or email for the account
        username: String,
        /// The password to store
        password: String,
    },

    /// Retrieve a specific password entry
    Get {
        /// Name of the password entry to retrieve
        name: String,
    },

    /// List all stored password entries
    List,

    /// Start the web server for remote access
    Server {
        /// Port number for the web server (default: 8080)
        #[arg(short, long, default_value = "8080")]
        port: u16,
    },
}

// ====================
// MAIN APPLICATION
// ====================

/// Main entry point for the password manager application
///
/// Handles command-line argument parsing and dispatches to appropriate
/// functionality based on user input (CLI commands, GUI, or server mode).
#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    if cli.gui {
        // Launch graphical user interface
        run_gui();
    } else {
        // Handle CLI commands
        match cli.command {
            Some(Commands::Add { name, username, password }) => {
                add_password(name, username, password);
            }
            Some(Commands::Get { name }) => {
                get_password(name);
            }
            Some(Commands::List) => {
                list_passwords();
            }
            Some(Commands::Server { port }) => {
                run_server(port).await;
            }
            None => {
                println!("Please provide a command or use --gui for graphical interface");
                println!("Use --help for more information");
            }
        }
    }
}

// ====================
// CRYPTOGRAPHIC FUNCTIONS
// ====================

/// Derives an encryption key from the master password using Argon2
///
/// # Arguments
/// * `master_password` - The master password to derive key from
///
/// # Returns
/// * `Key<Aes256Gcm>` - A 256-bit encryption key suitable for AES-GCM
///
/// # Security Notes
/// - Uses Argon2 with default parameters for key derivation
/// - Currently uses a hardcoded salt (should be random in production)
/// - The salt should be stored securely and be unique per user
fn derive_key(master_password: &str) -> Key<Aes256Gcm> {
    let salt = b"some_salt"; // TODO: Use random salt in production
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(master_password.as_bytes(), salt, &mut key)
        .unwrap();
    key.into()
}

/// Encrypts data using AES-256-GCM with a random nonce
///
/// # Arguments
/// * `data` - The plaintext data to encrypt
/// * `key` - The encryption key
///
/// # Returns
/// * `Vec<u8>` - Encrypted data with nonce prepended (nonce + ciphertext)
///
/// # Security Notes
/// - Generates a new random nonce for each encryption
/// - Nonce is prepended to ciphertext for storage
/// - Uses AES-256-GCM for authenticated encryption
fn encrypt_data(data: &str, key: &Key<Aes256Gcm>) -> Vec<u8> {
    let cipher = Aes256Gcm::new(key);
    let nonce: [u8; 12] = rand::random(); // Generate random nonce
    let ciphertext = cipher
        .encrypt(&nonce.into(), data.as_bytes())
        .unwrap();

    // Prepend nonce to ciphertext for storage
    [nonce.to_vec(), ciphertext].concat()
}

/// Decrypts data that was encrypted with encrypt_data()
///
/// # Arguments
/// * `encrypted` - The encrypted data (nonce + ciphertext)
/// * `key` - The decryption key
///
/// # Returns
/// * `String` - The decrypted plaintext data
///
/// # Panics
/// Panics if decryption fails (due to wrong key, corrupted data, etc.)
fn decrypt_data(encrypted: &[u8], key: &Key<Aes256Gcm>) -> String {
    let cipher = Aes256Gcm::new(key);

    // Extract nonce and ciphertext from encrypted data
    let nonce = &encrypted[..12];
    let ciphertext = &encrypted[12..];

    let plaintext = cipher
        .decrypt(nonce.into(), ciphertext)
        .unwrap();

    String::from_utf8(plaintext).unwrap()
}

// ====================
// USER INTERFACE FUNCTIONS
// ====================

/// Prompts the user to enter their master password securely
///
/// # Returns
/// * `String` - The entered master password
///
/// # Security Notes
/// - Uses rpassword to hide password input
/// - Exits program if empty password is entered
/// - Password is not echoed to terminal
fn get_master_password() -> String {
    println!("{}", "🔐 Enter your master password:".cyan().bold());

    let password = read_password().unwrap();

    if password.is_empty() {
        println!("{}", "❌ Master password cannot be empty!".red());
        std::process::exit(1);
    }

    password
}

/// Loads and decrypts all password entries from disk
///
/// # Arguments
/// * `master_password` - The master password for decryption
///
/// # Returns
/// * `Vec<PasswordEntry>` - Vector of decrypted password entries
///
/// # Notes
/// - Returns empty vector if passwords file doesn't exist
/// - File is stored as "passwords.enc" in current directory
fn load_passwords(master_password: &str) -> Vec<PasswordEntry> {
    let path = "passwords.enc";

    if Path::new(path).exists() {
        // Read encrypted data from file
        let encrypted = fs::read(path).unwrap();

        // Derive key and decrypt
        let key = derive_key(master_password);
        let json = decrypt_data(&encrypted, &key);

        // Parse JSON into password entries
        serde_json::from_str(&json).unwrap_or_default()
    } else {
        // No password file exists yet
        Vec::new()
    }
}

/// Encrypts and saves all password entries to disk
///
/// # Arguments
/// * `passwords` - Vector of password entries to save
/// * `master_password` - The master password for encryption
///
/// # Notes
/// - Overwrites existing passwords.enc file
/// - Uses JSON serialization for structured storage
fn save_passwords(passwords: &Vec<PasswordEntry>, master_password: &str) {
    // Serialize passwords to JSON
    let json = serde_json::to_string(passwords).unwrap();

    // Encrypt the JSON data
    let key = derive_key(master_password);
    let encrypted = encrypt_data(&json, &key);

    // Write encrypted data to file
    fs::write("passwords.enc", encrypted).unwrap();
}

// ====================
// PASSWORD MANAGEMENT FUNCTIONS
// ====================

/// Adds a new password entry to the password store
///
/// # Arguments
/// * `name` - Unique identifier for the password entry
/// * `username` - Username/email for the account
/// * `password` - The password to store
///
/// # Behavior
/// - Validates that all fields are non-empty
/// - Checks for duplicate names
/// - Prompts for master password
/// - Saves updated password list
fn add_password(name: String, username: String, password: String) {
    // Validate input
    if name.is_empty() || username.is_empty() || password.is_empty() {
        println!("{}", "❌ All fields (name, username, password) are required!".red());
        return;
    }

    // Get master password and load existing passwords
    let master = get_master_password();
    let mut passwords = load_passwords(&master);

    // Check for duplicate names
    if passwords.iter().any(|p| p.name == name) {
        println!("{}", format!("⚠️  Password entry '{}' already exists. Use a different name.", name).yellow());
        return;
    }

    // Add new password entry
    passwords.push(PasswordEntry { name: name.clone(), username, password });

    // Save updated list
    save_passwords(&passwords, &master);
    println!("{}", format!("✅ Password '{}' added successfully!", name).green().bold());
}

/// Retrieves and displays a specific password entry
///
/// # Arguments
/// * `name` - Name of the password entry to retrieve
///
/// # Behavior
/// - Prompts for master password
/// - Searches for entry by name
/// - Displays entry details if found
/// - Shows helpful message if not found
fn get_password(name: String) {
    let master = get_master_password();
    let passwords = load_passwords(&master);

    if let Some(entry) = passwords.iter().find(|e| e.name == name) {
        // Display password entry details
        println!("{}", "🔍 Password found:".cyan().bold());
        println!("  {} {}", "Name:".blue().bold(), entry.name);
        println!("  {} {}", "Username:".blue().bold(), entry.username);
        println!("  {} {}", "Password:".blue().bold(), entry.password.red());
        println!();
        println!("{}", "⚠️  Keep your passwords secure!".yellow());
    } else {
        // Password not found
        println!("{}", format!("❌ No password found with name '{}'", name).red());
        println!("{}", "💡 Use 'list' command to see all available passwords".cyan());
    }
}

/// Lists all stored password entries in a formatted table
///
/// # Behavior
/// - Prompts for master password
/// - Displays formatted table of all passwords
/// - Shows helpful messages if no passwords exist
fn list_passwords() {
    let master = get_master_password();
    let passwords = load_passwords(&master);

    if passwords.is_empty() {
        println!("{}", "📭 No passwords stored yet.".yellow());
        println!("{}", "💡 Use 'add' command to add your first password".cyan());
        return;
    }

    // Display header
    println!("{}", format!("📋 Found {} password(s):", passwords.len()).cyan().bold());
    println!("{}", "─".repeat(50).blue());
    println!("{:<20} {:<30}", "NAME".bold(), "USERNAME".bold());
    println!("{}", "─".repeat(50).blue());

    // Display each password entry
    for entry in passwords {
        println!("{:<20} {:<30}", entry.name.green(), entry.username.cyan());
    }

    println!("{}", "─".repeat(50).blue());
    println!("{}", "💡 Use 'get <name>' to view password details".cyan());
}

// ====================
// GRAPHICAL USER INTERFACE
// ====================

/// Launches the graphical user interface using egui
///
/// Creates a native window with an intuitive interface for password management
/// including forms for adding passwords and a list view for existing entries.
fn run_gui() {
    let app = PasswordApp::default();
    let options = eframe::NativeOptions::default();
    eframe::run_native("Password Manager", options, Box::new(|_cc| Box::new(app))).unwrap();
}

/// Main application state for the GUI
#[derive(Default)]
struct PasswordApp {
    /// Current master password input
    master_password: String,
    /// Loaded password entries (decrypted)
    passwords: Vec<PasswordEntry>,
    /// Input field for new password name
    new_name: String,
    /// Input field for new password username
    new_username: String,
    /// Input field for new password
    new_password: String,
    /// Toggle for showing/hiding passwords in the list
    show_passwords: bool,
}

/// Implementation of the egui application trait for the password manager GUI
impl eframe::App for PasswordApp {
    /// Main GUI update function called each frame
    ///
    /// Renders the complete user interface including:
    /// - Master password input and loading
    /// - Form for adding new passwords
    /// - List of existing passwords with delete functionality
    /// - Security tips and user guidance
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            // Application header
            ui.vertical_centered(|ui| {
                ui.heading("🔐 Secure Password Manager");
                ui.add_space(10.0);
            });

            // ====================
            // MASTER PASSWORD SECTION
            // ====================
            ui.group(|ui| {
                ui.label("🔑 Master Password");
                ui.horizontal(|ui| {
                    ui.text_edit_singleline(&mut self.master_password);
                    if ui.button("🔓 Load Passwords").clicked() {
                        if !self.master_password.is_empty() {
                            self.passwords = load_passwords(&self.master_password);
                        }
                    }
                });
            });

            ui.add_space(20.0);

            // ====================
            // ADD PASSWORD SECTION
            // ====================
            ui.collapsing("➕ Add New Password", |ui| {
                ui.horizontal(|ui| {
                    ui.label("Name:");
                    ui.text_edit_singleline(&mut self.new_name);
                });
                ui.horizontal(|ui| {
                    ui.label("Username:");
                    ui.text_edit_singleline(&mut self.new_username);
                });
                ui.horizontal(|ui| {
                    ui.label("Password:");
                    ui.text_edit_singleline(&mut self.new_password);
                });
                ui.horizontal(|ui| {
                    if ui.button("✅ Add Password").clicked() {
                        if !self.new_name.is_empty() && !self.new_username.is_empty() && !self.new_password.is_empty() {
                            self.passwords.push(PasswordEntry {
                                name: self.new_name.clone(),
                                username: self.new_username.clone(),
                                password: self.new_password.clone(),
                            });
                            save_passwords(&self.passwords, &self.master_password);
                            self.new_name.clear();
                            self.new_username.clear();
                            self.new_password.clear();
                        }
                    }
                    if ui.button("🗑️ Clear").clicked() {
                        self.new_name.clear();
                        self.new_username.clear();
                        self.new_password.clear();
                    }
                });
            });

            ui.add_space(20.0);

            // ====================
            // PASSWORDS LIST SECTION
            // ====================
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.heading("📋 Stored Passwords");
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.checkbox(&mut self.show_passwords, "👁️ Show Passwords");
                    });
                });

                if self.passwords.is_empty() {
                    ui.colored_label(
                        egui::Color32::YELLOW,
                        "No passwords loaded. Enter master password and click 'Load Passwords'"
                    );
                } else {
                    ui.label(format!("Total: {} passwords", self.passwords.len()));

                    egui::ScrollArea::vertical().show(ui, |ui| {
                        let mut to_remove = Vec::new();

                        // Display each password entry
                        for (index, entry) in self.passwords.iter().enumerate() {
                            ui.group(|ui| {
                                ui.horizontal(|ui| {
                                    ui.label(format!("🔑 {}", entry.name));
                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                        if ui.button("🗑️ Delete").clicked() {
                                            to_remove.push(index);
                                        }
                                    });
                                });

                                ui.horizontal(|ui| {
                                    ui.label("👤 Username:");
                                    ui.label(&entry.username);
                                });

                                if self.show_passwords {
                                    ui.horizontal(|ui| {
                                        ui.label("🔒 Password:");
                                        ui.colored_label(egui::Color32::RED, &entry.password);
                                    });
                                }
                            });
                            ui.add_space(5.0);
                        }

                        // Remove deleted items (in reverse order to maintain indices)
                        for &index in to_remove.iter().rev() {
                            if index < self.passwords.len() {
                                self.passwords.remove(index);
                            }
                        }

                        // Save changes if any deletions occurred
                        if !to_remove.is_empty() {
                            save_passwords(&self.passwords, &self.master_password);
                        }
                    });
                }
            });

            ui.add_space(20.0);
            ui.separator();
            ui.colored_label(
                egui::Color32::BLUE,
                "💡 Tip: Keep your master password secure and use strong, unique passwords for each account!"
            );
        });
    }
}

// ====================
// WEB SERVER
// ====================

/// Starts a simple web server for remote password synchronization
///
/// Provides basic upload/download endpoints for encrypted password data.
/// This is a simple implementation for demonstration purposes.
///
/// # Arguments
/// * `port` - Port number to bind the server to
///
/// # Endpoints
/// - `POST /upload` - Upload encrypted password data
/// - `GET /download` - Download encrypted password data
///
/// # Security Notes
/// - No authentication implemented
/// - Data is stored in memory only (not persisted)
/// - Should not be used in production without proper security measures
async fn run_server(port: u16) {
    // Shared state for storing uploaded data (in production, use a database)
    let shared_state = Arc::new(Mutex::new(None::<Vec<u8>>));

    // Configure routes
    let app = Router::new()
        .route("/upload", post({
            let state = Arc::clone(&shared_state);
            move |body: Body| async move {
                let bytes = to_bytes(body, usize::MAX).await.unwrap();
                *state.lock().await = Some(bytes.to_vec());
                "Uploaded"
            }
        }))
        .route("/download", get({
            let state = Arc::clone(&shared_state);
            move || async move {
                if let Some(data) = &*state.lock().await {
                    data.clone()
                } else {
                    Vec::new()
                }
            }
        }));

    let addr = format!("0.0.0.0:{}", port);
    println!("Server running on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
