# 🔐 Secure Password Manager

A modern, secure password manager built in Rust with both CLI and GUI interfaces. Features local encrypted storage using AES-GCM encryption and optional cross-device synchronization.

## ✨ Features

- **🔒 Military-Grade Encryption**: AES-256-GCM encryption with Argon2 key derivation
- **🖥️ Dual Interface**: Both command-line and graphical user interfaces
- **📱 Cross-Device Sync**: Optional REST API server for syncing across devices
- **🎨 Beautiful UI**: Professional GUI with egui framework
- **⚡ Fast & Secure**: Written in Rust for performance and memory safety
- **🔍 Easy Management**: Add, view, list, and delete passwords with ease
- **📚 Well-Documented**: Comprehensive code documentation with examples
- **🏗️ Clean Architecture**: Organized code structure with clear separation of concerns

## 🚀 Installation

### Prerequisites
- Rust 1.70+ (install from [rustup.rs](https://rustup.rs/))
- For GUI: System libraries for egui (usually pre-installed on macOS/Linux)

### Build from Source
```bash
git clone https://github.com/TheRealMasterK/Password-Manager-Rust.git
cd Password-Manager-Rust/password-manager
cargo build --release
```

## 📖 Usage

### Command Line Interface (CLI)

#### Add a Password
```bash
cargo run -- add "gmail" "user@example.com" "mySecurePassword123"
```

#### Get a Password
```bash
cargo run -- get "gmail"
```

#### List All Passwords
```bash
cargo run -- list
```

#### Start Sync Server
```bash
cargo run -- server --port 8080
```

#### Launch GUI
```bash
cargo run -- --gui
```

### Graphical User Interface (GUI)

Launch the GUI with:
```bash
cargo run -- --gui
```

The GUI provides:
- **Master Password Input**: Enter your master password to unlock stored passwords
- **Add New Passwords**: Easy form to add new password entries
- **View Passwords**: Toggle visibility of stored passwords
- **Delete Passwords**: Remove unwanted entries
- **Professional Layout**: Clean, modern interface with icons and colors

## 🔧 Configuration

### Master Password
- Your master password is used to encrypt/decrypt all stored passwords
- Choose a strong, memorable master password
- Never share your master password with anyone

### Storage
- Passwords are stored locally in `passwords.enc` file
- All data is encrypted with your master password
- File is created automatically on first use

## 🌐 Cross-Device Synchronization

### Server Mode
Run the password manager in server mode to enable syncing:
```bash
cargo run -- server --port 8080
```

### Client Sync
- Upload your encrypted password database to the server
- Download and merge with local passwords
- All data remains encrypted during transfer

### API Endpoints
- `POST /upload` - Upload encrypted password data
- `GET /download` - Download encrypted password data

## 🛡️ Security Features

- **AES-256-GCM Encryption**: Industry-standard encryption
- **Argon2 Key Derivation**: Memory-hard function for password hashing
- **Local Storage**: No cloud dependency by default
- **Memory Safety**: Rust's guarantees prevent common vulnerabilities
- **No Plaintext Storage**: Passwords are never stored in plaintext

## 📁 Project Structure

```
Password-Manager-Rust/
├── password-manager/          # Main password manager application
│   ├── src/main.rs           # Application entry point
│   ├── Cargo.toml            # Dependencies and configuration
│   └── passwords.enc         # Encrypted password storage (created on first use)
└── static-analyzer/          # Code analysis tool
    ├── src/main.rs           # Static analyzer implementation
    └── Cargo.toml            # Dependencies
```

## 🏗️ Architecture

### Core Components
- **Encryption Module**: Handles AES-GCM encryption/decryption
- **Storage Module**: Manages encrypted file I/O
- **CLI Module**: Command-line argument parsing and execution
- **GUI Module**: Graphical interface with egui
- **Server Module**: REST API for cross-device sync

### Code Quality
- **Comprehensive Documentation**: Every function and struct is fully documented
- **Clear Code Organization**: Logical separation with section headers and comments
- **Security Comments**: Inline security notes and best practices
- **Error Handling**: Proper error handling with descriptive messages
- **Type Safety**: Strong typing throughout for compile-time guarantees

### Data Flow
1. User enters master password
2. Password is used to derive encryption key via Argon2
3. Encrypted data is loaded from file and decrypted
4. User operations are performed on decrypted data
5. Data is re-encrypted and saved to file

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

- Keep your master password secure and memorable
- Regularly backup your `passwords.enc` file
- This tool is for personal use - consider enterprise solutions for business use
- Always use strong, unique passwords for each account

## 🐛 Troubleshooting

### Common Issues

**"Master password incorrect"**
- Verify you're entering the correct master password
- Passwords are case-sensitive

**"No passwords found"**
- Check if `passwords.enc` file exists in the current directory
- Ensure you've added passwords using the `add` command

**GUI won't start**
- Ensure system has GUI libraries installed
- Try running from a graphical environment

**Server connection issues**
- Check if the server is running on the correct port
- Verify firewall settings allow connections

## 🔄 Version History

- **v0.1.0**: Initial release with CLI and GUI interfaces
  - AES-256-GCM encryption
  - Basic CRUD operations
  - Cross-device sync capability
  - Professional UI design

## 🙏 Acknowledgments

- [Rust Programming Language](https://www.rust-lang.org/) - For memory safety and performance
- [egui](https://github.com/emilk/egui) - For the beautiful GUI framework
- [AES-GCM](https://github.com/RustCrypto/AEADs) - For encryption implementation
- [Argon2](https://github.com/RustCrypto/password-hashes) - For secure key derivation

---

**Made with ❤️ in Rust**
