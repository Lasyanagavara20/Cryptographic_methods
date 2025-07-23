# Secure Communication Using RSA and AES (Python)

This Python script demonstrates a **hybrid cryptography system** that combines **RSA** and **AES** for secure communication. It also implements **digital signatures** for message integrity and authentication.

---

## 🔐 Features

- Generate a 2048-bit RSA key pair
- Generate a 128-bit AES session key
- Encrypt the AES key using RSA (asymmetric encryption)
- Encrypt a plaintext message using AES (symmetric encryption)
- Sign the original plaintext message using RSA digital signature
- Decrypt the AES key and message
- Verify the digital signature to ensure message integrity

---

## 📁 Project Structure

Cryptographic_methods/
├── images/
│   └── output.png
├── secure_comm.py
└── README.md
