import os
from dotenv import load_dotenv
from pathlib import Path

load_dotenv()

# مسیرهای فایل‌ها
BASE_DIR = Path(__file__).resolve().parent
USER_DATA_FILE = BASE_DIR / "user_data.json"
SECRET_KEY_FILE = BASE_DIR / "secret.key"
LOG_FILE = BASE_DIR / "bot.log"

# تنظیمات امنیتی
class SecurityConfig:
    MAX_RETRIES = 3
    RATE_LIMIT = 5  
    SESSION_TIMEOUT = 3600  
    ENCRYPTION_KEY_LENGTH = 32

class Config:
    TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
    BASE_URI_PROXY = os.environ.get('BASE_URI_PROXY', 'https://uiapi.saapa.ir')
    USER_DATA_FILE = str(USER_DATA_FILE)
    SECRET_KEY_FILE = str(SECRET_KEY_FILE)
    LOG_FILE = str(LOG_FILE)
    
    # تنظیمات امنیتی
    SECURITY = SecurityConfig()
    
    @classmethod
    def validate(cls):
        """اعتبارسنجی تنظیمات"""
        if not cls.TOKEN:
            raise ValueError("TELEGRAM_BOT_TOKEN not set in environment variables")
        
        # اطمینان از وجود فایل‌های مورد نیاز
        for file_path in [USER_DATA_FILE, SECRET_KEY_FILE]:
            if not file_path.exists():
                file_path.touch()
                file_path.chmod(0o600)