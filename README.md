# RSA-AES-File-Encryptor

---

# 🔐 Secure File Transfer System (Java + Cryptography)

A **secure client-server file transfer application** built using **Java Socket Programming, Swing GUI, and Modern Cryptography (RSA + AES-GCM)**.

This project ensures that files are transferred securely over the network using **hybrid encryption**:

* RSA (asymmetric encryption) for secure key exchange
* AES-256 GCM (symmetric encryption) for fast and secure file encryption

It also includes a **GUI-based client and server** with real-time progress tracking and manual decryption control.

---

## 🚀 Features

### 🔹 Secure File Transfer

* Hybrid encryption using **RSA + AES-256**
* End-to-end encrypted file transmission
* AES-GCM provides **confidentiality + integrity check**

### 🔹 GUI-Based Client & Server

* Built using **Java Swing**
* File selection with browse option
* Upload progress bar
* Server status & logs panel
* Manual decryption button on server

### 🔹 Advanced Security Implementation

* RSA-2048 public/private key pair generation
* AES-256 session key generation
* Secure AES key exchange using RSA encryption
* GCM mode ensures tamper detection

### 🔹 Multithreading Support

* Server handles multiple connections using thread pool
* Client sends file in background thread (GUI remains responsive)

---

## 🏗️ Project Structure

```
ml_project.cn
│
├── Client.java      → GUI Client for sending encrypted files
├── Server.java      → GUI Server for receiving & decrypting files
├── Crypto.java      → Cryptographic utilities (RSA, AES, key handling)
```

---

## 🧠 How It Works (Architecture)

### Step 1: Connection Establishment

1. Client connects to server via socket
2. Server sends RSA public key to client

### Step 2: Secure Key Exchange

3. Client generates AES-256 session key
4. AES key encrypted using server RSA public key
5. Encrypted AES key sent to server
6. Server decrypts AES key using RSA private key

### Step 3: Secure File Transfer

7. Client encrypts file using AES-GCM
8. Encrypted file streamed to server
9. Server stores encrypted file temporarily

### Step 4: Manual Decryption (Server)

10. User clicks **Decrypt File**
11. Server decrypts file using AES key + IV
12. Original file restored securely

---

## 🔐 Cryptography Used

| Algorithm    | Purpose                    |
| ------------ | -------------------------- |
| RSA-2048     | Secure key exchange        |
| AES-256 GCM  | File encryption            |
| SecureRandom | IV generation              |
| OAEP Padding | Secure RSA encryption      |
| GCM Mode     | Integrity + authentication |

---

## 🖥️ GUI Preview (Concept)

### Client Side

* Select file
* Enter server IP & port
* Send encrypted file
* Progress bar & logs

### Server Side

* Start/Stop server
* View logs
* Receive encrypted file
* Click "Decrypt File" to restore

---

## ⚙️ Requirements

* Java JDK 8 or above
* Any Java IDE (IntelliJ / Eclipse / VS Code)
* Same network or localhost testing

---

## ▶️ How to Run

### Step 1: Compile

```
javac ml_project/cn/*.java
```

### Step 2: Start Server

Run:

```
java ml_project.cn.server
```

* Click **Start Server**
* Default port: 8080

### Step 3: Start Client

Run:

```
java ml_project.cn.Client
```

* Select file
* Enter server IP (127.0.0.1 for local)
* Click **Send File**

### Step 4: Decrypt on Server

* After receiving file
* Click **Decrypt File**
* Decrypted file saved in `received/` folder

---

## 📂 Output Files

```
received/
│
├── filename.ext.enc        → Encrypted file (temporary)
└── DECRYPTED_filename.ext  → Final decrypted file
```

---

## 🧪 Learning Outcomes

This project demonstrates:

* Socket Programming in Java
* Hybrid Cryptography Implementation
* AES-GCM Encryption
* RSA Key Exchange
* Java Swing GUI
* Multithreading in Java
* Secure File Handling

---

## 🎯 Use Cases

* Secure file sharing system
* Cybersecurity academic project
* Computer networks mini/major project
* Cryptography demonstration
* Portfolio project for placements

---

## 🔮 Future Improvements

* Multiple file transfer support
* Drag & drop file upload
* Cloud storage integration
* User authentication system
* End-to-end chat + file transfer
* Progress tracking on server
* Dark mode UI

---

## 👨‍💻 Author

Developed as a **Secure File Transfer System using Java & Cryptography**
for learning **Computer Networks + Cyber Security + Java GUI Development**

---

## ⭐ If you like this project

Give it a star on GitHub and use it in your portfolio to stand out in placements!
