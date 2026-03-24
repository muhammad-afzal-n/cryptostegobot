# 🔐 CryptoStegoBot

![Python Version](https://img.shields.io/badge/Python-3.8%2B-blue)
![Telegram API](https://img.shields.io/badge/Telegram_Bot_API-v20%2B-2CA5E0?logo=telegram)
![License](https://img.shields.io/badge/License-MIT-green)

**CryptoStegoBot** is a comprehensive, Telegram-based security utility bot. It provides accessible, on-the-go tools for data encryption, image-based steganography, statistical steganalysis, and cryptographic hash verification. 

This project was developed as a collaborative academic initiative at the **Rajadhani Institute of Engineering and Technology (RIET)**.

---

## ✨ Features

### 🔑 1. Cryptography
Perform secure text encryption and decryption directly in your chat:
* **AES-256 Encryption/Decryption:** Secure symmetric-key cryptography.
* **DES Encryption/Decryption:** Legacy symmetric-key cryptography.
* **RSA-2048 Operations:** Generate public/private key pairs, encrypt, and decrypt data using asymmetric cryptography.

### 🖼️ 2. Steganography
Hide secret text messages inside images without noticeably altering the image's appearance:
* **LSB (Least Significant Bit) Encoding:** Embeds text into the LSB of image pixels.
* **Message Extraction:** Decodes hidden data from stego-images.
* *Note: Optimizes and safely compresses images to meet Telegram's file size limits.*

### 🔍 3. Steganalysis
Analyze suspected images for hidden data using statistical methods:
* **Chi-Square Test:** Detects anomalies in pixel distributions common in LSB steganography.
* **LSB Distribution Analysis:** Analyzes the ratio of 0s and 1s in the least significant bits.
* **Histogram Variance:** Color channel (RGB) distribution analysis.

### #️⃣ 4. Hash Integrity Verification
Ensure your data has not been tampered with:
* Compute hashes using **MD5, SHA-1, and SHA-256**.
* Interactive hash verification tool to compare computed hashes against provided checksums.

### 🛡️ 5. Privacy & Security
* **Auto-Cleanup:** To maintain user privacy, the bot automatically clears all session data, keys, and images after 5 minutes of inactivity.

---

## 🛠️ Tech Stack

* **Language:** Python 3
* **Bot Framework:** `python-telegram-bot`
* **Cryptography:** `pycryptodome` (AES, DES, RSA, Padding)
* **Image Processing:** `Pillow` (PIL)
* **Data Analysis:** `numpy`
* **Hashing:** Python native `hashlib`

---

## 🚀 Installation & Setup

To run this bot locally, follow these steps:

### 1. Clone the Repository
```bash
git clone https://github.com/muhammad-afzal-n/cryptostegobot.git
cd cryptostegobot
```
### 2. Install Dependencies
It is recommended to use a virtual environment. Install the required packages via
```bash
pip install -r requirements.txt
```
### 3. Set Up the Bot Token

1. Open Telegram and message @BotFather to create a new bot and get your API token.
2. Set the token as an environment variable on your system:

### On Windows (Command Prompt):
```bash
set TELEGRAM_BOT_TOKEN=your_bot_token_here
```
### On Linux / Mac:
```bash
export TELEGRAM_BOT_TOKEN="your_bot_token_here"
```
### 4. Run the Bot
```bash
python3 crypto.py
```
### The Terminal should output: 

CryptoStegoBot Starting..


### Disclaimer:

This Bot is created for Educational and Academic Purposes.











