# utils.py
import jdatetime
import json
from datetime import datetime
import pytz
from cryptography.fernet import Fernet
from config import Config
import os
import logging

logger = logging.getLogger(__name__)

def get_jalali_dates():
    today = jdatetime.datetime.now()
    end_date = today + jdatetime.timedelta(days=5)
    
    current_date = today.strftime("%Y/%m/%d")
    end_date_str = end_date.strftime("%Y/%m/%d")
    
    return current_date, end_date_str

def generate_key():
    """تولید کلید رمزنگاری جدید"""
    key = Fernet.generate_key()
    with open(Config.SECRET_KEY_FILE, 'wb') as key_file:
        key_file.write(key)
    os.chmod(Config.SECRET_KEY_FILE, 0o600)  # تنظیم دسترسی‌های امن
    return key

def load_key():
    """بارگذاری کلید رمزنگاری"""
    if not os.path.exists(Config.SECRET_KEY_FILE):
        return generate_key()
    
    try:
        with open(Config.SECRET_KEY_FILE, 'rb') as key_file:
            return key_file.read()
    except Exception as e:
        logger.error(f"Error loading encryption key: {str(e)}")
        return generate_key()

def encrypt_data(data: dict) -> str:
    """رمزنگاری داده‌ها"""
    try:
        key = load_key()
        f = Fernet(key)
        json_data = json.dumps(data)
        encrypted_data = f.encrypt(json_data.encode())
        return encrypted_data.decode()
    except Exception as e:
        logger.error(f"Error encrypting data: {str(e)}")
        raise

def decrypt_data(encrypted_data: str) -> dict:
    """رمزگشایی داده‌ها"""
    try:
        key = load_key()
        f = Fernet(key)
        decrypted_data = f.decrypt(encrypted_data.encode())
        return json.loads(decrypted_data.decode())
    except Exception as e:
        logger.error(f"Error decrypting data: {str(e)}")
        raise

def sanitize_input(text: str) -> str:
    """پاکسازی ورودی کاربر"""
    return text.strip()

def validate_session(session_data: dict) -> bool:
    """اعتبارسنجی نشست کاربر"""
    if not session_data or 'timestamp' not in session_data:
        return False
    
    session_time = datetime.fromisoformat(session_data['timestamp'])
    current_time = datetime.now(pytz.UTC)
    time_diff = (current_time - session_time).total_seconds()
    
    return time_diff < Config.SECURITY.SESSION_TIMEOUT

def log_security_event(event_type: str, details: dict):
    """ثبت رویدادهای امنیتی"""
    logger.warning(f"Security Event - {event_type}: {json.dumps(details)}")