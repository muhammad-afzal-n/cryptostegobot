# 🔐 CryptoStegoBot

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python Version"/>
  <img src="https://img.shields.io/badge/Telegram_Bot_API-v20%2B-2CA5E0?style=for-the-badge&logo=telegram&logoColor=white" alt="Telegram API"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License"/>
  <img src="https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge" alt="Status"/>
</p>

<p align="center">
  <b>A Telegram-based security utility bot for encryption, steganography, steganalysis, and hash verification — all from your chat.</b>
</p>

---

## 📖 Overview

**CryptoStegoBot** is a comprehensive, Telegram-based security utility bot that puts powerful cryptographic and steganographic tools right in your pocket. Whether you need to encrypt sensitive text, hide messages inside images, detect hidden data, or verify file integrity — CryptoStegoBot handles it all through a simple, conversational interface.

> 🎓 This project was developed as a collaborative academic initiative at the **Rajadhani Institute of Engineering and Technology (RIET)**.

---

## ✨ Features

### 🔑 1. Cryptography
Perform secure text encryption and decryption directly in your Telegram chat:

| Algorithm | Type | Key Size |
|-----------|------|----------|
| AES | Symmetric | 256-bit |
| DES | Symmetric (Legacy) | 56-bit |
| RSA | Asymmetric | 2048-bit |

- **AES-256** — Industry-standard symmetric encryption for maximum security.
- **DES** — Legacy symmetric encryption for academic and compatibility use cases.
- **RSA-2048** — Generate key pairs, encrypt, and decrypt using asymmetric cryptography.

---

### 🖼️ 2. Steganography
Conceal secret text messages inside ordinary images without any visible alteration:

- **LSB (Least Significant Bit) Encoding** — Embeds text into the least significant bits of image pixels.
- **Message Extraction** — Decodes hidden data from stego-images with precision.

> 💡 The bot automatically optimizes and compresses images to comply with Telegram's file size limits.

---

### 🔍 3. Steganalysis
Statistically analyze images to detect the presence of hidden data:

- **Chi-Square Test** — Detects pixel distribution anomalies typical of LSB steganography.
- **LSB Distribution Analysis** — Examines the ratio of 0s and 1s in the least significant bits.
- **Histogram Variance** — Performs RGB color channel distribution analysis.

---

### #️⃣ 4. Hash Integrity Verification
Verify that your data hasn't been tampered with:

- Compute cryptographic hashes using **MD5**, **SHA-1**, and **SHA-256**.
- Built-in interactive verification tool to compare computed hashes against provided checksums.

---

### 🛡️ 5. Privacy & Security
- **Auto-Cleanup** — All session data, encryption keys, and images are automatically purged after **5 minutes of inactivity**, ensuring your sensitive data never lingers.

---

## 🛠️ Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Python 3.8+ |
| Bot Framework | `python-telegram-bot` v20+ |
| Cryptography | `pycryptodome` (AES, DES, RSA) |
| Image Processing | `Pillow` (PIL) |
| Data Analysis | `numpy` |
| Hashing | Python built-in `hashlib` |

---

## 🚀 Installation & Setup

### Prerequisites
- Python 3.8 or higher
- A Telegram account
- A bot token from [@BotFather](https://t.me/BotFather)

---

### 1. Clone the Repository

```bash
git clone https://github.com/muhammad-afzal-n/cryptostegobot.git
cd cryptostegobot
```

### 2. Create a Virtual Environment *(Recommended)*

```bash
# Create virtual environment
python3 -m venv venv

# Activate it
# On Linux / macOS:
source venv/bin/activate

# On Windows:
venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Your Bot Token

Get your API token from [@BotFather](https://t.me/BotFather) on Telegram, then set it as an environment variable:

**Linux / macOS:**
```bash
export TELEGRAM_BOT_TOKEN="your_bot_token_here"
```

**Windows (Command Prompt):**
```cmd
set TELEGRAM_BOT_TOKEN=your_bot_token_here
```

**Windows (PowerShell):**
```powershell
$env:TELEGRAM_BOT_TOKEN="your_bot_token_here"
```

### 5. Run the Bot

```bash
python3 crypto.py
```

**Expected output:**
```
CryptoStegoBot Starting...
```

Your bot is now live and ready to use on Telegram! 🎉

---

## 📁 Project Structure

```
cryptostegobot/
├── crypto.py           # Main bot entry point
├── requirements.txt    # Python dependencies
└── README.md           # Project documentation
```

---

## 👥 Contributors

This project was built with dedication by:

<table>
  <tr>
    <td align="center">
      <b>Muhammad Afzal N</b><br/>
      <sub>Developer & Maintainer</sub><br/>
      <a href="https://github.com/muhammad-afzal-n">@muhammad-afzal-n</a>
    </td>
    <td align="center">
      <b>Deepu Pradeep</b><br/>
      <sub>Contributor</sub>
    </td>
  </tr>
</table>

> 🎓 Developed at **Rajadhani Institute of Engineering and Technology (RIET)**

---

## ⚠️ Disclaimer

> This bot is developed strictly for **educational and academic purposes**. The cryptographic and steganographic tools provided are intended to demonstrate concepts in information security. The authors are not responsible for any misuse of this software.

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

<p align="center">Made with ❤️ for learning and exploration in cybersecurity</p>
