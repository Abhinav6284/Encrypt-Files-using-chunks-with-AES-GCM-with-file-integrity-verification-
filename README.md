
## 🔒 Security Features

- **AES-256-GCM Encryption**: Industry-standard encryption algorithm
- **Cryptographic Randomness**: Secure key and nonce generation using Python's `secrets` module
- **Chunk-based Processing**: Handles large files efficiently without loading entirely into memory
- **No Key Storage**: Encryption keys are never stored on the server
- **Input Validation**: Comprehensive validation of file uploads and encryption keys
- **Secure File Handling**: Uses secure filename handling to prevent path traversal attacks

## 🎨 Design Philosophy

This tool follows a **minimal and professional** design approach:

- **Clean Typography**: System fonts for native appearance
- **Minimal Color Palette**: Professional blue-gray (#2c3e50) and muted grays
- **Intuitive Navigation**: Tab-based navigation for clear workflow
- **Responsive Layout**: Mobile-first design that works on all devices
- **Consistent Spacing**: Uniform spacing and padding throughout
- **Subtle Interactions**: Clean hover states and transitions

## 🔧 Technical Details

### Encryption Process
1. File is read in 64KB chunks for memory efficiency
2. Each chunk is encrypted using AES-256-GCM with a unique nonce
3. Encrypted data is structured with length prefixes for robust parsing
4. Output can be saved as Base64-encoded text or raw binary

### API Endpoints
- `GET /` - Serves the main interface
- `GET /generate-key` - Generates a new encryption key
- `POST /encrypt` - Encrypts uploaded files
- `POST /decrypt` - Decrypts uploaded files

## 🚨 Security Considerations

- **Keep your encryption keys safe**: Without the key, encrypted files cannot be recovered
- **Use strong, unique keys**: Always generate new keys for different encryption sessions
- **Secure key storage**: Consider using a password manager or secure offline storage
- **File size limits**: Default maximum file size is 100MB (configurable in app.py)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🐛 Bug Reports & Feature Requests

If you encounter any issues or have suggestions for improvements, please:

1. Check existing issues on GitHub
2. Create a new issue with detailed information
3. Include steps to reproduce for bug reports
4. Provide clear use cases for feature requests

## 📚 Additional Resources

- [Cryptography Documentation](https://cryptography.io/en/latest/)
- [Flask Documentation](https://flask.palletsprojects.com/)
- [AES-GCM Specification](https://tools.ietf.org/html/rfc5116)

## ⚠️ Disclaimer

This tool is provided for educational and personal use. While it implements industry-standard encryption, users should evaluate their specific security requirements and consider professional security audits for production use cases.

---

**Made with ❤️ for secure file encryption**
