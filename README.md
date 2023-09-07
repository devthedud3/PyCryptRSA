# PyCryptRSA: File Encryption and Decryption with RSA

![Python Version](https://img.shields.io/badge/Python-3.7-blue.svg)

## Introduction

PyCryptRSA is a Python script that allows you to encrypt and decrypt files using the RSA (Rivest–Shamir–Adleman) encryption algorithm. RSA is widely used for securing data transmission and storage, and this tool provides an easy way to apply it to your files.

## Features

- Encrypt files with a public key.
- Decrypt files with the corresponding private key.
- Supports various key sizes for customization.

## Installation

1. Clone the repository to your local machine:

   ```bash
   git clone https://github.com/devthedud3/PyCryptRSA.git
   ```

2. Change into the project directory:

   ```bash
   cd PyCryptRSA
   ```

## Usage

### 1. Generate RSA Keys

PyCryptRSA will generate RSA key pairs (public and private keys) for you. 
Ensure that the file(s) you want to encrypt/decrypt are in the same directory as
this file.

The keys will be created in this same folder labeled `encryption-keys/your-file-name`

### 2. Encrypt or Decrypt a File

To encrypt a file, run the following command, and simply follow the prompt as directed.

```bash
python RSA.py
```

The system will then give you the option to encrypt or decrypt and then ask you to enter the filename, including EXT.

This will generate an encrypted file called `encrypted_file.enc`.


## Security Considerations

- **Keep your private key secure:** Ensure that your private key (`private.pem`) is kept confidential and stored securely.
- **Key size:** Consider using larger key sizes for increased security, especially when dealing with sensitive data.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Thanks to the Python community for providing powerful cryptographic libraries.
- Inspired by the need for easy-to-use file encryption tools.

## Disclaimer

This tool is provided for educational, informational, and portfolio purposes only. Use it responsibly and always follow best practices for data security and encryption.
