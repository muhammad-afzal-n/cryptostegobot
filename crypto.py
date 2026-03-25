"""
CryptoStegoBot: A Telegram-Based Security Bot
Features:
- Cryptography (AES, DES, RSA)
- Steganography (LSB-based)
- Steganalysis (Statistical detection)
- Hash Integrity Verification (MD5, SHA-1, SHA-256)

Authors: Muhammad Afzal N & Deepu Pradeep
Guided By: Ms Aiswarya SS
Department: Computer Science and Engineering, RIET
"""

import os
import io
import hashlib
import logging
import asyncio
from datetime import datetime, timedelta
from typing import Optional, Tuple
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    ConversationHandler,
    ContextTypes,
    filters
)
from PIL import Image
import numpy as np
from Crypto.Cipher import AES, DES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

# Enable logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Configuration
INACTIVITY_TIMEOUT = 300  # 5 minutes in seconds

# Conversation states
(CRYPTO_CHOICE, CRYPTO_TEXT, CRYPTO_KEY,
 STEGO_CHOICE, STEGO_IMAGE, STEGO_MESSAGE,
 HASH_CHOICE, HASH_TEXT) = range(8)


class CryptoModule:
    """Handles cryptographic operations: AES, DES, RSA"""
    
    @staticmethod
    def aes_encrypt(plaintext: str, key: str) -> str:
        """Encrypt text using AES-256"""
        # Pad or trim key to 32 bytes for AES-256
        key_bytes = key.encode('utf-8')[:32].ljust(32, b'\0')
        
        cipher = AES.new(key_bytes, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
        iv = base64.b64encode(cipher.iv).decode('utf-8')
        ct = base64.b64encode(ct_bytes).decode('utf-8')
        return f"{iv}::{ct}"
    
    @staticmethod
    def aes_decrypt(ciphertext: str, key: str) -> str:
        """Decrypt AES-256 encrypted text"""
        try:
            key_bytes = key.encode('utf-8')[:32].ljust(32, b'\0')
            iv, ct = ciphertext.split("::")
            iv_bytes = base64.b64decode(iv)
            ct_bytes = base64.b64decode(ct)
            
            cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
            pt = unpad(cipher.decrypt(ct_bytes), AES.block_size)
            return pt.decode('utf-8')
        except Exception as e:
            return f"Decryption failed: {str(e)}"
    
    @staticmethod
    def des_encrypt(plaintext: str, key: str) -> str:
        """Encrypt text using DES"""
        # DES requires 8-byte key
        key_bytes = key.encode('utf-8')[:8].ljust(8, b'\0')
        
        cipher = DES.new(key_bytes, DES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(plaintext.encode('utf-8'), DES.block_size))
        iv = base64.b64encode(cipher.iv).decode('utf-8')
        ct = base64.b64encode(ct_bytes).decode('utf-8')
        return f"{iv}::{ct}"
    
    @staticmethod
    def des_decrypt(ciphertext: str, key: str) -> str:
        """Decrypt DES encrypted text"""
        try:
            key_bytes = key.encode('utf-8')[:8].ljust(8, b'\0')
            iv, ct = ciphertext.split("::")
            iv_bytes = base64.b64decode(iv)
            ct_bytes = base64.b64decode(ct)
            
            cipher = DES.new(key_bytes, DES.MODE_CBC, iv_bytes)
            pt = unpad(cipher.decrypt(ct_bytes), DES.block_size)
            return pt.decode('utf-8')
        except Exception as e:
            return f"Decryption failed: {str(e)}"
    
    @staticmethod
    def rsa_generate_keys() -> Tuple[str, str]:
        """Generate RSA key pair"""
        key = RSA.generate(2048)
        private_key = key.export_key().decode('utf-8')
        public_key = key.publickey().export_key().decode('utf-8')
        return private_key, public_key
    
    @staticmethod
    def rsa_encrypt(plaintext: str, public_key_str: str) -> str:
        """Encrypt text using RSA public key"""
        try:
            public_key = RSA.import_key(public_key_str.encode('utf-8'))
            cipher = PKCS1_OAEP.new(public_key)
            ct_bytes = cipher.encrypt(plaintext.encode('utf-8'))
            return base64.b64encode(ct_bytes).decode('utf-8')
        except Exception as e:
            return f"Encryption failed: {str(e)}"
    
    @staticmethod
    def rsa_decrypt(ciphertext: str, private_key_str: str) -> str:
        """Decrypt RSA encrypted text"""
        try:
            private_key = RSA.import_key(private_key_str.encode('utf-8'))
            cipher = PKCS1_OAEP.new(private_key)
            ct_bytes = base64.b64decode(ciphertext)
            pt = cipher.decrypt(ct_bytes)
            return pt.decode('utf-8')
        except Exception as e:
            return f"Decryption failed: {str(e)}"


class SteganographyModule:
    """Handles LSB-based image steganography"""
    
    @staticmethod
    def encode_message(image: Image.Image, message: str) -> Image.Image:
        """Embed message into image using LSB technique"""
        # Convert message to binary
        binary_message = ''.join(format(ord(char), '08b') for char in message)
        binary_message += '1111111111111110'  # End delimiter
        
        img_array = np.array(image)
        
        # Flatten array for faster processing
        flat_array = img_array.flatten()
        
        # Modify LSBs using vectorized operations
        for i in range(len(binary_message)):
            if i < len(flat_array):
                # Clear LSB and set new bit
                flat_array[i] = (flat_array[i] & 0xFE) | int(binary_message[i])
        
        # Reshape back to original dimensions
        img_array = flat_array.reshape(img_array.shape)
        
        return Image.fromarray(img_array)
    
    @staticmethod
    def decode_message(image: Image.Image) -> str:
        """Extract hidden message from image using LSB technique"""
        img_array = np.array(image)
        
        # Flatten array and extract LSBs
        flat_array = img_array.flatten()
        binary_message = ''.join(str(pixel & 1) for pixel in flat_array)
        
        # Split into 8-bit chunks and decode
        message = ""
        for i in range(0, len(binary_message) - 8, 8):
            byte = binary_message[i:i+8]
            if len(byte) < 8:
                break
            
            # Check for end delimiter (0xFE = 11111110)
            if byte == '11111110':
                break
            
            try:
                char_code = int(byte, 2)
                # Only accept printable ASCII and common characters
                if 32 <= char_code <= 126 or char_code in [9, 10, 13]:  # Printable + tab/newline
                    message += chr(char_code)
                elif char_code == 0:  # Null character might indicate end
                    break
            except (ValueError, OverflowError):
                break
        
        return message


class SteganalysisModule:
    """Detects potential steganography in images"""
    
    @staticmethod
    def chi_square_test(image: Image.Image) -> Tuple[float, str]:
        """Perform chi-square test to detect LSB steganography"""
        img_array = np.array(image)
        
        # Flatten and get LSBs
        pixels = img_array.flatten()
        lsb_array = pixels & 1
        
        # Count pairs
        pairs = {}
        for i in range(0, len(lsb_array) - 1, 2):
            pair = (lsb_array[i], lsb_array[i+1])
            pairs[pair] = pairs.get(pair, 0) + 1
        
        # Calculate chi-square statistic
        expected = len(lsb_array) / 4
        chi_square = 0
        for count in pairs.values():
            chi_square += ((count - expected) ** 2) / expected if expected > 0 else 0
        
        # Interpret results
        if chi_square > 7.815:  # 95% confidence level, df=3
            result = "⚠️ SUSPICIOUS - Likely contains hidden data"
        else:
            result = "✅ CLEAN - No steganography detected"
        
        return chi_square, result
    
    @staticmethod
    def histogram_analysis(image: Image.Image) -> dict:
        """Analyze color histogram for anomalies"""
        img_array = np.array(image)
        
        results = {}
        for channel, color in enumerate(['Red', 'Green', 'Blue']):
            hist, _ = np.histogram(img_array[:,:,channel], bins=256, range=(0, 256))
            
            # Calculate histogram variance
            variance = np.var(hist)
            results[color] = variance
        
        return results
    
    @staticmethod
    def lsb_analysis(image: Image.Image) -> dict:
        """Analyze LSB distribution"""
        img_array = np.array(image)
        lsbs = img_array & 1
        
        unique, counts = np.unique(lsbs, return_counts=True)
        total = lsbs.size
        
        distribution = {int(k): (int(v), round(v/total*100, 2)) 
                       for k, v in zip(unique, counts)}
        
        # Ideal ratio is 50:50
        ratio_deviation = abs(50 - distribution.get(0, (0, 0))[1])
        
        return {
            'distribution': distribution,
            'deviation': ratio_deviation,
            'suspicious': ratio_deviation > 5
        }


class HashModule:
    """Handles hash integrity verification"""
    
    @staticmethod
    def compute_hash(data: str, algorithm: str) -> str:
        """Compute hash of given data"""
        data_bytes = data.encode('utf-8')
        
        if algorithm == 'MD5':
            return hashlib.md5(data_bytes).hexdigest()
        elif algorithm == 'SHA1':
            return hashlib.sha1(data_bytes).hexdigest()
        elif algorithm == 'SHA256':
            return hashlib.sha256(data_bytes).hexdigest()
        else:
            return "Unsupported algorithm"
    
    @staticmethod
    def verify_hash(data: str, provided_hash: str, algorithm: str) -> bool:
        """Verify if computed hash matches provided hash"""
        computed = HashModule.compute_hash(data, algorithm)
        return computed.lower() == provided_hash.lower()


# Bot Command Handlers

# Dictionary to store user activity timestamps and cleanup tasks
user_activity = {}
cleanup_tasks = {}


async def schedule_cleanup(user_id: int, context: ContextTypes.DEFAULT_TYPE):
    """Schedule context cleanup after inactivity timeout"""
    # Cancel any existing cleanup task for this user
    if user_id in cleanup_tasks:
        cleanup_tasks[user_id].cancel()
    
    # Create new cleanup task
    async def cleanup():
        try:
            await asyncio.sleep(INACTIVITY_TIMEOUT)
            
            # Clear user context data
            if user_id in context.application.user_data:
                context.application.user_data[user_id].clear()
                logger.info(f"Cleared context for inactive user {user_id}")
            
            # Remove from tracking
            if user_id in user_activity:
                del user_activity[user_id]
            if user_id in cleanup_tasks:
                del cleanup_tasks[user_id]
                
        except asyncio.CancelledError:
            # Task was cancelled, cleanup scheduled again
            pass
    
    # Store and start the cleanup task
    cleanup_tasks[user_id] = asyncio.create_task(cleanup())


async def update_user_activity(user_id: int, context: ContextTypes.DEFAULT_TYPE):
    """Update user activity timestamp and reschedule cleanup"""
    user_activity[user_id] = datetime.now()
    await schedule_cleanup(user_id, context)


async def check_and_notify_timeout(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    """Check if user session timed out and notify if needed"""
    user_id = update.effective_user.id
    
    # If user has data but no recent activity, it means they timed out
    if user_id not in user_activity and context.user_data:
        await update.message.reply_text(
            "⏰ *Session Timeout*\n\n"
            "Your session expired due to 5 minutes of inactivity.\n"
            "All conversation data has been cleared for security.\n\n"
            "Please start over with your desired command:\n"
            "• /crypto - Cryptographic operations\n"
            "• /stego - Steganography\n"
            "• /hash - Hash verification\n"
            "• /steganalysis - Analyze images",
            parse_mode='Markdown'
        )
        return True
    
    # Update activity
    await update_user_activity(user_id, context)
    return False


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Start command - welcome message"""
    user_id = update.effective_user.id
    
    # Clear any existing context and reset activity tracking
    context.user_data.clear()
    await update_user_activity(user_id, context)
    
    welcome_text = """
🔐 *CryptoStegoBot* - Security Utility Bot

Welcome! I provide the following security features:

🔑 *Cryptography*
   • AES Encryption/Decryption
   • DES Encryption/Decryption
   • RSA Key Generation & Operations

🖼️ *Steganography*
   • Hide messages in images (LSB)
   • Extract hidden messages

🔍 *Steganalysis*
   • Detect hidden data in images
   • Statistical analysis

#️⃣ *Hash Verification*
   • MD5, SHA-1, SHA-256
   • Integrity checking

*Commands:*
/crypto - Cryptographic operations
/stego - Steganography operations
/steganalysis - Analyze images for hidden data
/hash - Hash verification
/help - Show this message

⏰ *Auto-Cleanup:* Session data is automatically cleared after 5 minutes of inactivity for security.

Developed by: RIET CSE Team
"""
    await update.message.reply_text(welcome_text, parse_mode='Markdown')


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Help command"""
    await start(update, context)


async def crypto_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Start cryptography workflow"""
    user_id = update.effective_user.id
    await update_user_activity(user_id, context)
    
    keyboard = [
        [InlineKeyboardButton("🔐 AES Encrypt", callback_data='aes_enc')],
        [InlineKeyboardButton("🔓 AES Decrypt", callback_data='aes_dec')],
        [InlineKeyboardButton("🔐 DES Encrypt", callback_data='des_enc')],
        [InlineKeyboardButton("🔓 DES Decrypt", callback_data='des_dec')],
        [InlineKeyboardButton("🔑 RSA Generate Keys", callback_data='rsa_gen')],
        [InlineKeyboardButton("🔐 RSA Encrypt", callback_data='rsa_enc')],
        [InlineKeyboardButton("🔓 RSA Decrypt", callback_data='rsa_dec')],
        [InlineKeyboardButton("❌ Cancel", callback_data='cancel')]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await update.message.reply_text(
        '🔑 *Cryptography Module*\n\nChoose an operation:',
        reply_markup=reply_markup,
        parse_mode='Markdown'
    )
    return CRYPTO_CHOICE


async def crypto_choice(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle cryptography choice"""
    query = update.callback_query
    await query.answer()
    
    user_id = update.effective_user.id
    await update_user_activity(user_id, context)
    
    choice = query.data
    context.user_data['crypto_operation'] = choice
    
    if choice == 'rsa_gen':
        # Generate RSA keys immediately
        private_key, public_key = CryptoModule.rsa_generate_keys()
        
        response = f"""
🔑 *RSA Key Pair Generated*

*Private Key:*
```
{private_key}
```

*Public Key:*
```
{public_key}
```

⚠️ *Keep your private key secure!*
"""
        await query.edit_message_text(response, parse_mode='Markdown')
        return ConversationHandler.END
    
    elif choice == 'cancel':
        await query.edit_message_text('Operation cancelled.')
        return ConversationHandler.END
    
    else:
        operation_names = {
            'aes_enc': 'AES Encryption',
            'aes_dec': 'AES Decryption',
            'des_enc': 'DES Encryption',
            'des_dec': 'DES Decryption',
            'rsa_enc': 'RSA Encryption',
            'rsa_dec': 'RSA Decryption'
        }
        
        if 'dec' in choice or choice == 'rsa_enc':
            prompt = "Please send the text to process:"
        else:
            prompt = "Please send the plaintext message:"
        
        await query.edit_message_text(
            f"🔐 *{operation_names.get(choice, 'Operation')}*\n\n{prompt}",
            parse_mode='Markdown'
        )
        return CRYPTO_TEXT


async def crypto_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Receive text for crypto operation"""
    user_id = update.effective_user.id
    await update_user_activity(user_id, context)
    
    context.user_data['crypto_text'] = update.message.text
    operation = context.user_data['crypto_operation']
    
    if operation in ['aes_enc', 'aes_dec', 'des_enc', 'des_dec']:
        key_length = "32 characters for AES" if 'aes' in operation else "8 characters for DES"
        await update.message.reply_text(f"Now send the encryption key ({key_length}):")
        return CRYPTO_KEY
    
    elif operation == 'rsa_enc':
        await update.message.reply_text("Send the RSA public key:")
        return CRYPTO_KEY
    
    elif operation == 'rsa_dec':
        await update.message.reply_text("Send the RSA private key:")
        return CRYPTO_KEY


async def crypto_key(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Process crypto operation with key"""
    user_id = update.effective_user.id
    await update_user_activity(user_id, context)
    
    key = update.message.text
    text = context.user_data['crypto_text']
    operation = context.user_data['crypto_operation']
    
    try:
        if operation == 'aes_enc':
            result = CryptoModule.aes_encrypt(text, key)
            await update.message.reply_text(f"🔐 *AES Encrypted:*\n```\n{result}\n```", parse_mode='Markdown')
        
        elif operation == 'aes_dec':
            result = CryptoModule.aes_decrypt(text, key)
            await update.message.reply_text(f"🔓 *AES Decrypted:*\n{result}", parse_mode='Markdown')
        
        elif operation == 'des_enc':
            result = CryptoModule.des_encrypt(text, key)
            await update.message.reply_text(f"🔐 *DES Encrypted:*\n```\n{result}\n```", parse_mode='Markdown')
        
        elif operation == 'des_dec':
            result = CryptoModule.des_decrypt(text, key)
            await update.message.reply_text(f"🔓 *DES Decrypted:*\n{result}", parse_mode='Markdown')
        
        elif operation == 'rsa_enc':
            result = CryptoModule.rsa_encrypt(text, key)
            await update.message.reply_text(f"🔐 *RSA Encrypted:*\n```\n{result}\n```", parse_mode='Markdown')
        
        elif operation == 'rsa_dec':
            result = CryptoModule.rsa_decrypt(text, key)
            await update.message.reply_text(f"🔓 *RSA Decrypted:*\n{result}", parse_mode='Markdown')
    
    except Exception as e:
        await update.message.reply_text(f"❌ Error: {str(e)}")
    
    return ConversationHandler.END


async def stego_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Start steganography workflow"""
    user_id = update.effective_user.id
    await update_user_activity(user_id, context)
    
    keyboard = [
        [InlineKeyboardButton("📝 Hide Message", callback_data='stego_hide')],
        [InlineKeyboardButton("🔍 Extract Message", callback_data='stego_extract')],
        [InlineKeyboardButton("❌ Cancel", callback_data='cancel')]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await update.message.reply_text(
        '🖼️ *Steganography Module*\n\nChoose an operation:',
        reply_markup=reply_markup,
        parse_mode='Markdown'
    )
    return STEGO_CHOICE


async def stego_choice(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle steganography choice"""
    query = update.callback_query
    await query.answer()
    
    user_id = update.effective_user.id
    await update_user_activity(user_id, context)
    
    choice = query.data
    context.user_data['stego_operation'] = choice
    
    if choice == 'cancel':
        await query.edit_message_text('Operation cancelled.')
        return ConversationHandler.END
    
    prompt = "Please send the cover image (PNG format recommended):"
    await query.edit_message_text(prompt)
    return STEGO_IMAGE


async def stego_image(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Receive image for steganography"""
    user_id = update.effective_user.id
    await update_user_activity(user_id, context)
    
    # Accept both photo and document
    if update.message.photo:
        # Download photo (get largest available)
        photo = update.message.photo[-1]
        
        # Check file size
        if photo.file_size and photo.file_size > 20 * 1024 * 1024:  # 20MB
            await update.message.reply_text("❌ Image too large! Please use an image under 20MB.")
            return STEGO_IMAGE
        
        await update.message.reply_text("⬇️ Downloading image...")
        
        try:
            file = await context.bot.get_file(photo.file_id)
            image_bytes = await file.download_as_bytearray()
        except Exception as e:
            await update.message.reply_text(f"❌ Failed to download image: {str(e)}")
            return STEGO_IMAGE
            
    elif update.message.document:
        # Accept document (for stego images sent as documents)
        document = update.message.document
        
        # Check if it's an image
        if not document.mime_type or not document.mime_type.startswith('image/'):
            await update.message.reply_text("❌ Please send an image file (PNG, JPG, etc.)")
            return STEGO_IMAGE
        
        # Check file size
        if document.file_size and document.file_size > 20 * 1024 * 1024:  # 20MB
            await update.message.reply_text("❌ File too large! Please use an image under 20MB.")
            return STEGO_IMAGE
        
        await update.message.reply_text("⬇️ Downloading document...")
        
        try:
            file = await context.bot.get_file(document.file_id)
            image_bytes = await file.download_as_bytearray()
        except Exception as e:
            await update.message.reply_text(f"❌ Failed to download document: {str(e)}")
            return STEGO_IMAGE
    else:
        await update.message.reply_text("❌ Please send an image (as photo or document)!")
        return STEGO_IMAGE
    
    # Save to context
    context.user_data['stego_image'] = image_bytes
    
    operation = context.user_data['stego_operation']
    
    if operation == 'stego_hide':
        await update.message.reply_text("✅ Image received! Now send the secret message to hide:")
        return STEGO_MESSAGE
    
    elif operation == 'stego_extract':
        # Extract message
        processing_msg = await update.message.reply_text("🔄 Extracting message...")
        
        try:
            image = Image.open(io.BytesIO(image_bytes))
            message = SteganographyModule.decode_message(image)
            
            # Try to delete processing message (ignore if fails)
            try:
                await processing_msg.delete()
            except:
                pass
            
            # Escape markdown special characters
            safe_message = message.replace('_', '\\_').replace('*', '\\*').replace('[', '\\[').replace('`', '\\`')
            await update.message.reply_text(f"🔍 *Extracted Message:*\n\n{safe_message}", parse_mode='Markdown')
        except Exception as e:
            # Try to delete processing message (ignore if fails)
            try:
                await processing_msg.delete()
            except:
                pass
            await update.message.reply_text(f"❌ Extraction failed: {str(e)}")
        
        return ConversationHandler.END


async def stego_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Hide message in image"""
    message = update.message.text
    image_bytes = context.user_data['stego_image']
    
    # Send processing message
    processing_msg = await update.message.reply_text("🔄 Processing image... Please wait.")
    
    try:
        # Load image
        image = Image.open(io.BytesIO(image_bytes)).convert('RGB')
        
        # Resize if too large (to prevent timeout)
        max_size = 1500
        if image.width > max_size or image.height > max_size:
            ratio = min(max_size / image.width, max_size / image.height)
            new_size = (int(image.width * ratio), int(image.height * ratio))
            image = image.resize(new_size, Image.Resampling.LANCZOS)
            await processing_msg.edit_text(f"🔄 Image resized to {new_size[0]}x{new_size[1]}...")
        
        # Encode message
        stego_image = SteganographyModule.encode_message(image, message)
        
        # Save to bytes with optimization
        output = io.BytesIO()
        stego_image.save(output, format='PNG', optimize=True, compress_level=6)
        output.seek(0)
        output.name = "stego_image.png"
        
        # Check file size
        file_size = output.getbuffer().nbytes / (1024 * 1024)  # MB
        
        # Try to delete processing message (ignore if fails)
        try:
            await processing_msg.delete()
        except:
            pass
        
        # Send as document (faster, no Telegram compression)
        if file_size < 20:  # Telegram limit
            await update.message.reply_document(
                document=output,
                filename="stego_image.png",
                caption=f"✅ Message hidden successfully!\n📦 Size: {file_size:.2f} MB\n\n💡 Download this file to extract the message later.",
                read_timeout=60,
                write_timeout=60,
                connect_timeout=60
            )
        else:
            await update.message.reply_text(
                f"⚠️ Output file is too large ({file_size:.2f} MB).\n"
                "Please use a smaller image (under 800x800) or shorter message."
            )
    
    except Exception as e:
        # Try to delete processing message (ignore if fails)
        try:
            await processing_msg.delete()
        except:
            pass
        
        error_msg = str(e)
        if "Timed out" in error_msg or "timeout" in error_msg.lower():
            await update.message.reply_text(
                "⏱️ Upload timed out. The image is too large.\n\n"
                "Try:\n"
                "• Use a smaller image (max 500x500 pixels)\n"
                "• Compress the image before uploading\n"
                "• Use a shorter message"
            )
        else:
            await update.message.reply_text(f"❌ Encoding failed: {error_msg}")
    
    return ConversationHandler.END


async def steganalysis_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Start steganalysis"""
    user_id = update.effective_user.id
    await update_user_activity(user_id, context)
    
    await update.message.reply_text(
        "🔍 *Steganalysis Module*\n\n"
        "Send an image to analyze for potential hidden data.\n"
        "I'll perform statistical tests including:\n"
        "• Chi-square test\n"
        "• LSB distribution analysis\n"
        "• Histogram analysis",
        parse_mode='Markdown'
    )


async def steganalysis_image(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Analyze image for steganography"""
    if not update.message.photo and not update.message.document:
        await update.message.reply_text("❌ Please send an image!")
        return
    
    # Send processing message
    processing_msg = await update.message.reply_text("🔍 Analyzing image... Please wait.")
    
    try:
        # Download image
        if update.message.photo:
            photo = update.message.photo[-1]
            file = await context.bot.get_file(photo.file_id)
        else:
            file = await context.bot.get_file(update.message.document.file_id)
        
        image_bytes = await file.download_as_bytearray()
        image = Image.open(io.BytesIO(image_bytes)).convert('RGB')
        
        # Resize if too large for faster analysis
        max_size = 800
        if image.width > max_size or image.height > max_size:
            ratio = min(max_size / image.width, max_size / image.height)
            new_size = (int(image.width * ratio), int(image.height * ratio))
            image = image.resize(new_size, Image.Resampling.LANCZOS)
        
        # Perform analysis
        chi_square, chi_result = SteganalysisModule.chi_square_test(image)
        lsb_result = SteganalysisModule.lsb_analysis(image)
        hist_result = SteganalysisModule.histogram_analysis(image)
        
        # Delete processing message
        try:
            await processing_msg.delete()
        except:
            pass
        
        # Format results
        response = f"""
🔍 *Steganalysis Report*

*Chi-Square Test:*
Chi-Square Value: {chi_square:.2f}
Result: {chi_result}

*LSB Distribution Analysis:*
0's: {lsb_result['distribution'].get(0, (0, 0))[0]} ({lsb_result['distribution'].get(0, (0, 0))[1]}%)
1's: {lsb_result['distribution'].get(1, (0, 0))[0]} ({lsb_result['distribution'].get(1, (0, 0))[1]}%)
Deviation from 50:50: {lsb_result['deviation']:.2f}%
Status: {'⚠️ SUSPICIOUS' if lsb_result['suspicious'] else '✅ NORMAL'}

*Histogram Variance:*
Red Channel: {hist_result['Red']:.2f}
Green Channel: {hist_result['Green']:.2f}
Blue Channel: {hist_result['Blue']:.2f}

*Overall Assessment:*
"""
        
        # Overall verdict
        suspicious_count = sum([
            chi_square > 7.815,
            lsb_result['suspicious']
        ])
        
        if suspicious_count >= 2:
            response += "⚠️ *HIGH PROBABILITY* of steganography detected!"
        elif suspicious_count == 1:
            response += "⚡ *MODERATE PROBABILITY* - Further investigation recommended"
        else:
            response += "✅ *LOW PROBABILITY* - Image appears clean"
        
        await update.message.reply_text(response, parse_mode='Markdown')
    
    except Exception as e:
        await update.message.reply_text(f"❌ Analysis failed: {str(e)}")


async def hash_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Start hash verification workflow"""
    user_id = update.effective_user.id
    await update_user_activity(user_id, context)
    
    keyboard = [
        [InlineKeyboardButton("MD5", callback_data='hash_md5')],
        [InlineKeyboardButton("SHA-1", callback_data='hash_sha1')],
        [InlineKeyboardButton("SHA-256", callback_data='hash_sha256')],
        [InlineKeyboardButton("Verify Hash", callback_data='hash_verify')],
        [InlineKeyboardButton("❌ Cancel", callback_data='cancel')]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await update.message.reply_text(
        '#️⃣ *Hash Verification Module*\n\nChoose an operation:',
        reply_markup=reply_markup,
        parse_mode='Markdown'
    )
    return HASH_CHOICE


async def hash_choice(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle hash choice"""
    query = update.callback_query
    await query.answer()
    
    user_id = update.effective_user.id
    await update_user_activity(user_id, context)
    
    choice = query.data
    context.user_data['hash_operation'] = choice
    
    if choice == 'cancel':
        await query.edit_message_text('Operation cancelled.')
        return ConversationHandler.END
    
    if choice == 'hash_verify':
        await query.edit_message_text(
            "Send the text whose hash you want to verify:"
        )
    else:
        await query.edit_message_text(
            f"Send the text to hash using {choice.split('_')[1].upper()}:"
        )
    
    return HASH_TEXT


async def hash_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Process hash operation"""
    user_id = update.effective_user.id
    await update_user_activity(user_id, context)
    
    text = update.message.text
    operation = context.user_data.get('hash_operation', '')
    
    # Check if this is the second message in verification flow
    if 'hash_text' in context.user_data and operation == 'hash_verify':
        # This is the hash+algorithm input
        return await hash_verify(update, context)
    
    if operation == 'hash_verify':
        # First message - store the text to verify
        context.user_data['hash_text'] = text
        await update.message.reply_text(
            "✅ *Text saved successfully!*\n\n"
            f"Text to verify: `{text[:50]}{'...' if len(text) > 50 else ''}`\n\n"
            "━━━━━━━━━━━━━━━━━━━━\n\n"
            "Now, send the hash in this *exact* format:\n"
            "`hash_value|ALGORITHM`\n\n"
            "⚠️ *Important:* Must include the | separator\n\n"
            "*Examples:*\n"
            "MD5:\n`5d41402abc4b2a76b9719d911017c592|MD5`\n\n"
            "SHA1:\n`356a192b7913b04c54574d18c28d46e6395428ab|SHA1`\n\n"
            "SHA256:\n`a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e|SHA256`",
            parse_mode='Markdown'
        )
        return HASH_TEXT
    
    else:
        # Compute hash
        algorithm = operation.split('_')[1].upper()
        
        # Normalize algorithm names to match HashModule expectations
        if algorithm == 'SHA1':
            algorithm = 'SHA1'
        elif algorithm == 'SHA256':
            algorithm = 'SHA256'
        elif algorithm == 'MD5':
            algorithm = 'MD5'
        
        hash_value = HashModule.compute_hash(text, algorithm)
        
        response = f"""
#️⃣ *Hash Computed*

*Algorithm:* {algorithm}
*Input:* {text[:50]}{'...' if len(text) > 50 else ''}

*Hash:*
```
{hash_value}
```

💡 *To verify this hash later:*
Send: `/hash` → Verify Hash
Then paste: `{hash_value}|{algorithm}`
"""
        await update.message.reply_text(response, parse_mode='Markdown')
        return ConversationHandler.END


async def hash_verify(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Verify hash"""
    try:
        hash_data = update.message.text.strip()
        
        # Parse input
        if '|' not in hash_data:
            await update.message.reply_text(
                "❌ *Invalid format!*\n\n"
                "You sent:\n"
                f"`{hash_data[:100]}{'...' if len(hash_data) > 100 else ''}`\n\n"
                "⚠️ *Missing the | separator*\n\n"
                "Required format: `hash_value|ALGORITHM`\n\n"
                "*Copy and paste one of these examples:*\n\n"
                "For MD5:\n"
                "`5d41402abc4b2a76b9719d911017c592|MD5`\n\n"
                "For SHA1:\n"
                "`a94a8fe5ccb19ba61c4c0873d391e987982fbbd3|SHA1`\n\n"
                "For SHA256:\n"
                "`9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08|SHA256`",
                parse_mode='Markdown'
            )
            return HASH_TEXT
        
        provided_hash, algorithm = hash_data.split('|', 1)
        provided_hash = provided_hash.strip()
        algorithm = algorithm.strip().upper()
        
        # Normalize algorithm names - handle common variations
        algorithm_map = {
            'MD5': 'MD5',
            'SHA-1': 'SHA1',
            'SHA1': 'SHA1',
            'SHA-256': 'SHA256',
            'SHA256': 'SHA256'
        }
        
        if algorithm in algorithm_map:
            algorithm = algorithm_map[algorithm]
        
        # Validate algorithm
        if algorithm not in ['MD5', 'SHA1', 'SHA256']:
            await update.message.reply_text(
                "❌ Invalid algorithm!\n\n"
                f"You sent: `{algorithm}`\n\n"
                "Supported algorithms:\n"
                "• MD5\n"
                "• SHA1 or SHA-1\n"
                "• SHA256 or SHA-256\n\n"
                "Example: `abc123|SHA256`",
                parse_mode='Markdown'
            )
            return HASH_TEXT
        
        text = context.user_data.get('hash_text', '')
        if not text:
            await update.message.reply_text("❌ No text found to verify. Please start over with /hash")
            return ConversationHandler.END
        
        # Compute actual hash
        computed_hash = HashModule.compute_hash(text, algorithm)
        
        # Verify - case insensitive comparison
        is_valid = computed_hash.lower() == provided_hash.lower()
        
        response = f"""
#️⃣ *Hash Verification Result*

*Algorithm:* {algorithm}
*Input Text:* `{text[:50]}{'...' if len(text) > 50 else ''}`

*Provided Hash:*
```
{provided_hash}
```

*Computed Hash:*
```
{computed_hash}
```

*Result:* {'✅ *MATCH* - Hashes are identical!' if is_valid else '❌ *MISMATCH* - Hashes are different!'}
"""
        
        if not is_valid:
            response += "\n\n⚠️ *Possible reasons:*\n• Text was modified\n• Hash is incorrect\n• Wrong algorithm selected"
        
        await update.message.reply_text(response, parse_mode='Markdown')
    
    except Exception as e:
        await update.message.reply_text(
            f"❌ Error: {str(e)}\n\n"
            "Please use format: `hash_value|ALGORITHM`\n\n"
            "Supported algorithms: MD5, SHA1, SHA256\n"
            "Example: `5d41402abc4b2a76b9719d911017c592|MD5`",
            parse_mode='Markdown'
        )
    
    return ConversationHandler.END


async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Cancel conversation"""
    await update.message.reply_text('Operation cancelled.')
    return ConversationHandler.END


def main():
    """Main function to run the bot"""
    
    # Fetch token from environment variable
    TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
    if not TOKEN:
       raise ValueError("No token provided. Please set the TELEGRAM_BOT_TOKEN environment variable.")

    
    # Create application
    application = Application.builder().token(TOKEN).build()
    
    # Command handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    
    # Cryptography conversation handler
    crypto_conv = ConversationHandler(
        entry_points=[CommandHandler("crypto", crypto_start)],
        states={
            CRYPTO_CHOICE: [CallbackQueryHandler(crypto_choice)],
            CRYPTO_TEXT: [MessageHandler(filters.TEXT & ~filters.COMMAND, crypto_text)],
            CRYPTO_KEY: [MessageHandler(filters.TEXT & ~filters.COMMAND, crypto_key)]
        },
        fallbacks=[CommandHandler("cancel", cancel)]
    )
    application.add_handler(crypto_conv)
    
    # Steganography conversation handler
    stego_conv = ConversationHandler(
        entry_points=[CommandHandler("stego", stego_start)],
        states={
            STEGO_CHOICE: [CallbackQueryHandler(stego_choice)],
            STEGO_IMAGE: [
                MessageHandler(filters.PHOTO, stego_image),
                MessageHandler(filters.Document.IMAGE, stego_image)
            ],
            STEGO_MESSAGE: [MessageHandler(filters.TEXT & ~filters.COMMAND, stego_message)]
        },
        fallbacks=[CommandHandler("cancel", cancel)]
    )
    application.add_handler(stego_conv)
    
    # Steganalysis handler
    application.add_handler(CommandHandler("steganalysis", steganalysis_start))
    application.add_handler(MessageHandler(
        filters.PHOTO | filters.Document.IMAGE,
        steganalysis_image
    ))
    
    # Hash conversation handler
    hash_conv = ConversationHandler(
        entry_points=[CommandHandler("hash", hash_start)],
        states={
            HASH_CHOICE: [CallbackQueryHandler(hash_choice)],
            HASH_TEXT: [MessageHandler(filters.TEXT & ~filters.COMMAND, hash_text)]
        },
        fallbacks=[CommandHandler("cancel", cancel)]
    )
    application.add_handler(hash_conv)
    
    # Start bot
    logger.info("CryptoStegoBot starting...")
    application.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == '__main__':
    main()
