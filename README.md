# 🔐 Encryption Tool - README

## 🌟 Overview  
This application provides a comprehensive set of encryption and decryption algorithms for secure data transformation. It supports both classical ciphers (like Caesar and Vigenère) and modern cryptographic algorithms (like AES, DES, and RSA). The tool is built using **Qt** and **OpenSSL**, offering a user-friendly GUI for encryption/decryption operations.  


## ✨ Features  

### 🔒 Supported Encryption Algorithms  
- **Caesar Cipher**  
- **Vigenère Cipher**  
- **XOR Cipher**  
- **Base64 Encoding**  
- **AES (256-bit)**  
- **DES**  
- **RSA** (Key Generation, Encryption, Decryption)  
- **SHA-256 Hashing**  
- **MD5 Hashing**  

### 🔓 Supported Decryption Algorithms  
- All the above encryption methods (where applicable)  

### 🛠️ Additional Features  
- ✅ RSA key pair generation  
- 🔑 Input validation for key lengths  
- ❌ Error handling for cryptographic operations  


## ⚙️ Requirements  
- **Operating System**: 🐧 Linux, 🪟 Windows, or 🍎 macOS  
- **Dependencies**:  
  - **Qt 5** or later  
  - **OpenSSL** library  
  - **C++17** compatible compiler  


## 📥 Installation  
1. **Install Qt**:  
   - Download from [Qt's official website](https://www.qt.io/).  

2. **Install OpenSSL**:  
   - **Linux**: `sudo apt-get install libssl-dev` (Debian/Ubuntu)  
   - **Windows**: Download from [Win32 OpenSSL](https://slproweb.com/products/Win32OpenSSL.html)  
   - **macOS**: `brew install openssl`  

3. **Build the Project**:  
   - Open the `.pro` file in **Qt Creator**.  
   - Configure `INCLUDEPATH` and `LIBS` in the `.pro` file if needed.  
   - Build and run the project.  


## 🚀 Usage  
1. **Input**:  
   - ✏️ Enter plaintext (or ciphertext for decryption) in the **"Plaintext"** field.  
   - 🔑 For algorithms requiring a key, enter it in the **"Key"** field.  

2. **Select Algorithm**:  
   - 🎛️ Choose encryption/decryption from the left panel.  
   - For **RSA**, use **"Generate RSA Key"** to create a key pair.  

3. **Execute**:  
   - 🏁 Click **"Execute"** to perform the operation.  
   - 📜 Results appear in the **"Cypher"** (or decrypted text) field.  


## 📝 Notes  
- **Key Requirements**:  
  - **AES**: 32-character key (256-bit).  
  - **DES**: 8-character key.  
  - **RSA**: Use generated key pairs.  
- **Hashing (SHA-256/MD5)**:  
  - 🔄 One-way hashes; "decryption" only verifies matches.  
- **Base64**:  
  - 🔄 Encoding/decoding for text representation of binary data.  


## 🛠️ Troubleshooting  
- **OpenSSL Errors**: Ensure paths in `.pro` are correct.  
- **Key Errors**: Verify key length/format.  
- **Build Issues**: Check Qt + C++17 compatibility.  


## 📜 License  
This project is **open-source**. Modify and distribute freely.  


