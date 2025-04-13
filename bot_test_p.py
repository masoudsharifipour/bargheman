import asyncio
import json
import logging
import requests
import re
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
from telegram import Update, ReplyKeyboardMarkup, ReplyKeyboardRemove
from telegram.ext import (
    ApplicationBuilder, ContextTypes,
    CommandHandler, MessageHandler, filters,
    ConversationHandler
)

from utils import get_jalali_dates
from cryptography.fernet import Fernet
import base64
import os
from datetime import time, datetime, timedelta
import pytz
from config import Config
from telegram.ext import Application

# تنظیمات امنیتی
MAX_RETRIES = 3
RATE_LIMIT = 5  # تعداد درخواست‌های مجاز در دقیقه
MOBILE_PATTERN = r'^09[0-9]{9}$'
OTP_PATTERN = r'^\d{6}$'

TOKEN = Config.TOKEN
USER_DATA_FILE = Config.USER_DATA_FILE

# --- تنظیمات لاگ ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('bot.log')
    ]
)
logger = logging.getLogger(__name__)

# --- مراحل گفتگو ---
GET_MOBILE, GET_OTP, SELECT_BILL = range(3)

# --- اعتبارسنجی ورودی‌ها ---
def validate_mobile(mobile: str) -> bool:
    """اعتبارسنجی شماره موبایل"""
    return bool(re.match(MOBILE_PATTERN, mobile))

def validate_otp(otp: str) -> bool:
    """اعتبارسنجی کد OTP"""
    return bool(re.match(OTP_PATTERN, otp))

# --- مدیریت خطا ---
async def safe_api_call(func, *args, **kwargs):
    """تابع کمکی برای فراخوانی API با مدیریت خطا"""
    for attempt in range(MAX_RETRIES):
        try:
            return await func(*args, **kwargs)
        except Exception as e:
            logger.error(f"Attempt {attempt + 1} failed: {str(e)}")
            if attempt == MAX_RETRIES - 1:
                raise
            await asyncio.sleep(1)

# --- دکمه‌ها ---
def get_menu_markup(chat_id: str = None) -> ReplyKeyboardMarkup:
    """تابع برای ساخت منوی دینامیک بر اساس وضعیت کاربر"""
    if chat_id and chat_id in user_data:
        # کاربر عضو است
        buttons = [
            ["📊 بررسی وضعیت خاموشی"],
            ["❌ حذف عضویت"]
        ]
    else:
        # کاربر عضو نیست
        buttons = [
            ["✅ عضویت جهت اطلاع‌رسانی"]
        ]
    return ReplyKeyboardMarkup(buttons, resize_keyboard=True)

# --- مدیریت خطاهای عمومی ---
async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE):
    logger.error(msg="Exception while handling an update:", exc_info=context.error)
    if update and isinstance(update, Update):
        try:
            await update.message.reply_text("⚠️ خطایی رخ داد. لطفاً دوباره تلاش کنید.")
        except:
            pass
# اضافه کردن این توابع به فایل
def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

def load_key():
    try:
        return open("secret.key", "rb").read()
    except FileNotFoundError:
        generate_key()
        return open("secret.key", "rb").read()

KEY = load_key()
fernet = Fernet(KEY)

def encrypt_data(data: dict) -> str:
    json_data = json.dumps(data).encode('utf-8')
    encrypted_data = fernet.encrypt(json_data)
    return encrypted_data.decode('utf-8')

def decrypt_data(encrypted_data: str) -> dict:
    decrypted_data = fernet.decrypt(encrypted_data.encode('utf-8'))
    return json.loads(decrypted_data.decode('utf-8'))

# --- لود و ذخیره داده‌های کاربران ---
def load_user_data():
    try:
        with open(USER_DATA_FILE, "r") as f:
            encrypted_data = json.load(f)
            return {k: decrypt_data(v) for k, v in encrypted_data.items()}
    except (FileNotFoundError, json.JSONDecodeError):
        return {}
    except Exception as e:
        logger.error(f"Error decrypting user data: {str(e)}")
        return {}

def save_user_data(data):
    encrypted_data = {k: encrypt_data(v) for k, v in data.items()}
    with open(USER_DATA_FILE, "w") as f:
        json.dump(encrypted_data, f, indent=4, ensure_ascii=False)

user_data = load_user_data()

# --- توابع API ---
async def send_otp(mobile: str):
    url = "https://uiapi.saapa.ir/api/otp/sendCode"
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "origin": "https://ios.bargheman.com",
        "referer": "https://ios.bargheman.com/",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    }
    payload = {"mobile": mobile}
    
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=15)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"Error sending OTP: {str(e)}")
        return None

async def verify_otp(mobile: str, code: str):
    url = "https://uiapi.saapa.ir/api/otp/verifyCode"
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "origin": "https://ios.bargheman.com",
        "referer": "https://ios.bargheman.com/",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    }
    payload = {
        "mobile": mobile,
        "code": code,
        "request_source": 5,
        "device_token": ""
    }
    
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=15)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"Error verifying OTP: {str(e)}")
        return None
    
def create_session():
    session = requests.Session()
    retries = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[500, 502, 503, 504]
    )
    session.mount('https://', HTTPAdapter(max_retries=retries))
    return session

async def get_user_bills(auth_token: str):
    url = "https://uiapi.saapa.ir/api/ebills/GetBills"
    headers = {
        "accept": "application/json",
        "authorization": f"Bearer {auth_token}",
        "content-type": "application/json",
        "origin": "https://ios.bargheman.com",
        "referer": "https://ios.bargheman.com/",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=50)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"Error getting bills: {str(e)}")
        return None

async def check_and_notify(context: ContextTypes.DEFAULT_TYPE):
    logger.info("🔍 شروع بررسی خودکار خاموشی‌ها...")
    
    for chat_id, user_info in user_data.items():
        try:
            if not all(k in user_info for k in ['token', 'bill_id']):
                continue
                
            # دریافت خاموشی‌ها با تابع جدید
            result = await get_blackouts(user_info['token'], user_info['bill_id'])
            
            if not result:
                continue
                
            # ساخت پیام اطلاع‌رسانی
            message = f"⚠️ هشدار خاموشی برای بازه {result['date_range']['from']} تا {result['date_range']['to']}:\n\n"
            
            if result['occurred']:
                message += "\n🔴 خاموشی‌های رخ داده:\n"
                for i, item in enumerate(result['occurred'], 1):
                    message += (
                        f"{i}. 📅 {item.get('outage_date', '?')} "
                        f"⏰ {item.get('outage_start_time', '?')}-{item.get('outage_stop_time', '?')}\n"
                        f"📍 {item.get('outage_address', '?')}\n\n"
                    )
            
            if result['planned']:
                message += "\n🟡 خاموشی‌های برنامه‌ریزی شده:\n"
                for i, item in enumerate(result['planned'], 1):
                    message += (
                        f"{i}. 📅 {item.get('outage_date', '?')} "
                        f"⏰ {item.get('outage_start_time', '?')}-{item.get('outage_stop_time', '?')}\n"
                        f"📍 {item.get('outage_address', '?')}\n\n"
                    )
            
            await context.bot.send_message(
                chat_id=chat_id,
                text=message,
                disable_notification=False
            )
            
        except Exception as e:
            logger.error(f"Error processing user {chat_id}: {str(e)}")

async def get_blackouts(token: str, bill_id: str):
    """دریافت لیست خاموشی‌ها با همان منطق check_blackouts اما فقط بازگشت داده"""
    headers = {
        "accept": "application/json",
        "authorization": f"Bearer {token}",
        "content-type": "application/json",
        "origin": "https://ios.bargheman.com",
        "referer": "https://ios.bargheman.com/",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    }
    
    DATE, TO_DATE = get_jalali_dates()
    logger.info(f"Getting blackouts from {DATE} to {TO_DATE} for bill {bill_id}")
    
    try:
        session = create_session()
        
        # 1. دریافت خاموشی‌های رخ داده
        r1 = session.post(
            "https://uiapi.saapa.ir/api/ebills/BlackoutsReport",
            headers=headers,
            json={"bill_id": bill_id, "date": DATE},
            timeout=30
        )
        r1.raise_for_status()
        
        # 2. دریافت خاموشی‌های برنامه‌ریزی شده
        r2 = session.post(
            "https://uiapi.saapa.ir/api/ebills/PlannedBlackoutsReport",
            headers=headers,
            json={"bill_id": bill_id, "from_date": DATE, "to_date": TO_DATE},
            timeout=30
        )
        r2.raise_for_status()
        
        data1 = r1.json().get("data", [])
        data2 = r2.json().get("data", [])
        
        # ساخت ساختار یکسان برای همه خاموشی‌ها
        blackouts = {
            "occurred": data1,
            "planned": data2,
            "date_range": {
                "from": DATE,
                "to": TO_DATE
            }
        }
        
        return blackouts
        
    except requests.exceptions.Timeout:
        logger.error("Timeout in getting blackouts")
        return None
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error in getting blackouts: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error in getting blackouts: {str(e)}", exc_info=True)
        return None
        
    # --- بررسی خاموشی ---
async def check_blackouts(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = str(update.message.chat_id)
    user = user_data.get(chat_id, {})
    
    # لاگ اطلاعات کاربر برای دیباگ
    logger.info(f"Checking blackouts for user: {user}")
    
    if not user.get('token') or not user.get('bill_id'):
        error_msg = "⚠️ شما هنوز وارد نشده‌اید یا قبضی انتخاب نکرده‌اید."
        logger.warning(error_msg)
        await update.message.reply_text(
            error_msg, 
            reply_markup=get_menu_markup(chat_id)
        )
        return
    
    DATE, TO_DATE = get_jalali_dates()
    logger.info(f"Checking blackouts from {DATE} to {TO_DATE}")
    
    headers = {
        "accept": "application/json",
        "authorization": f"Bearer {user['token']}",
        "content-type": "application/json",
        "origin": "https://ios.bargheman.com",
        "referer": "https://ios.bargheman.com/",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    }
    
    try:
        await update.message.reply_text(f"🔍 در حال بررسی برای بازه زمانی {DATE} تا {TO_DATE}...")
        
        # استفاده از session با retry
        session = create_session()
        
        # درخواست اول - خاموشی‌های رخ داده
        r1 = session.post(
            "https://uiapi.saapa.ir/api/ebills/BlackoutsReport",
            headers=headers,
            json={"bill_id": user['bill_id'], "date": DATE},
            timeout=30
        )
        logger.info(f"BlackoutsReport response: {r1.status_code} - {r1.text}")
        r1.raise_for_status()
        
        # درخواست دوم - خاموشی‌های برنامه‌ریزی شده
        r2 = session.post(
            "https://uiapi.saapa.ir/api/ebills/PlannedBlackoutsReport",
            headers=headers,
            json={"bill_id": user['bill_id'], "from_date": DATE, "to_date": TO_DATE},
            timeout=30
        )
        logger.info(f"PlannedBlackoutsReport response: {r2.status_code} - {r2.text}")
        r2.raise_for_status()
        
        data1 = r1.json().get("data", [])
        data2 = r2.json().get("data", [])

        if not data1 and not data2:
            await update.message.reply_text(
                "✅ هیچ خاموشی در بازه زمانی جستجو یافت نشد.",
                reply_markup=get_menu_markup(chat_id)
            )
            return

        msg = "📢 گزارش خاموشی:\n"
        if data1:
            msg += "\n🔴 خاموشی‌های رخ داده:\n"
            for i, item in enumerate(data1, 1):
                msg += (
                    f"{i}. 📅 {item.get('outage_date', '?')} "
                    f"⏰ {item.get('outage_start_time', '?')}-{item.get('outage_stop_time', '?')}\n"
                    f"📍 {item.get('outage_address', '?')}\n"
                )
        
        if data2:
            msg += "\n🟡 خاموشی‌های برنامه‌ریزی شده:\n"
            for i, item in enumerate(data2, 1):
                msg += (
                    f"{i}. 📅 {item.get('outage_date', '?')} "
                    f"⏰ {item.get('outage_start_time', '?')}-{item.get('outage_stop_time', '?')}\n"
                    f"📍 {item.get('outage_address', '?')}\n"
                )

        await update.message.reply_text(
            msg,
            reply_markup=get_menu_markup(chat_id)
        )
        
    except requests.exceptions.Timeout:
        error_msg = "⏳ سرور پاسخگو نیست. لطفاً چند دقیقه دیگر تلاش کنید."
        logger.error(error_msg)
        await update.message.reply_text(
            error_msg,
            reply_markup=get_menu_markup(chat_id)
        )
    except requests.exceptions.RequestException as e:
        error_msg = f"❌ خطا در ارتباط با سرور: {str(e)}"
        logger.error(error_msg)
        await update.message.reply_text(
            error_msg,
            reply_markup=get_menu_markup(chat_id)
        )
    except Exception as e:
        error_msg = f"❌ خطای ناشناخته: {str(e)}"
        logger.error(error_msg, exc_info=True)
        await update.message.reply_text(
            error_msg,
            reply_markup=get_menu_markup(chat_id)
        )

# --- دستور /start ---
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = str(update.message.chat_id)
    await update.message.reply_text(
        "سلام! به ربات اطلاع‌رسانی خاموشی خوش آمدید.\nلطفاً یک گزینه انتخاب کنید:",
        reply_markup=get_menu_markup(chat_id)
    )

# --- شروع فرآیند عضویت ---
async def start_registration(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = str(update.message.chat_id)
    
    # بررسی آیا کاربر قبلاً عضو شده
    if chat_id in user_data:
        user = user_data[chat_id]
        await update.message.reply_text(
            f"⚠️ شما قبلاً عضو شده‌اید:\n"
            f"📱 شماره: {user['mobile']}\n"
            f"🔹 قبض: {user['bill_title']}\n\n"
            f"برای تغییر اطلاعات، لطفاً ابتدا عضویت خود را حذف کنید.",
            reply_markup=get_menu_markup(chat_id)  # تغییر اینجا
        )
        return ConversationHandler.END
    
    await update.message.reply_text(
        "لطفاً شماره موبایل خود را وارد کنید (مثال: 09123456789):",
        reply_markup=ReplyKeyboardRemove()
    )
    return GET_MOBILE

# --- دریافت شماره موبایل و ارسال OTP ---
async def get_mobile(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """دریافت و اعتبارسنجی شماره موبایل"""
    mobile = update.message.text.strip()
    
    if not validate_mobile(mobile):
        await update.message.reply_text(
            "⚠️ شماره موبایل نامعتبر است. لطفاً شماره موبایل را به درستی وارد کنید."
        )
        return GET_MOBILE
    
    try:
        await safe_api_call(send_otp, mobile)
        context.user_data['mobile'] = mobile
        await update.message.reply_text(
            "کد تایید به شماره شما ارسال شد. لطفاً کد را وارد کنید:",
            reply_markup=ReplyKeyboardRemove()
        )
        return GET_OTP
    except Exception as e:
        logger.error(f"Error in get_mobile: {str(e)}")
        await update.message.reply_text(
            "❌ خطا در ارسال کد تایید. لطفاً دوباره تلاش کنید."
        )
        return ConversationHandler.END

# --- دریافت و تأیید OTP ---
async def get_otp(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """دریافت و اعتبارسنجی کد OTP"""
    otp = update.message.text.strip()
    
    if not validate_otp(otp):
        await update.message.reply_text(
            "⚠️ کد تایید نامعتبر است. لطفاً کد 6 رقمی را به درستی وارد کنید."
        )
        return GET_OTP
    
    try:
        mobile = context.user_data.get('mobile')
        if not mobile:
            raise ValueError("Mobile number not found in context")
            
        result = await safe_api_call(verify_otp, mobile, otp)
        if result:
            context.user_data['auth_token'] = result
            token = result['data']['Token']
            context.user_data['token'] = token
            
            await update.message.reply_text("⏳ در حال دریافت قبض‌ها...")
            bills_response = await get_user_bills(token)
            
            if not bills_response or bills_response.get('status') != 200:
                raise ValueError("خطا در دریافت قبض‌ها")
            
            bills = bills_response['data'].get('bill_data', [])
            if not bills:
                await update.message.reply_text(
                    "لطفا به سامانه مراجعه کرده و اطلاعات قبض خود را تعریف کنید. ⚠️ هیچ قبضی یافت نشد.",
                    reply_markup=get_menu_markup(str(update.message.chat_id))
                )
                return ConversationHandler.END
            
            context.user_data['bills'] = bills
            keyboard = [[f"{bill['bill_title']} ({bill['bill_identifier']})"] for bill in bills]
            keyboard.append(['انصراف'])
            
            await update.message.reply_text(
                "لطفاً قبض مورد نظر را انتخاب کنید:",
                reply_markup=ReplyKeyboardMarkup(keyboard, resize_keyboard=True)
            )
            return SELECT_BILL
        else:
            await update.message.reply_text(
                "❌ کد تایید نامعتبر است. لطفاً دوباره تلاش کنید."
            )
            return GET_OTP
    except Exception as e:
        logger.error(f"Error in get_otp: {str(e)}")
        await update.message.reply_text(
            "❌ خطا در تایید کد. لطفاً دوباره تلاش کنید."
        )
        return ConversationHandler.END

# --- انتخاب قبض و تکمیل عضویت ---
async def select_bill(update: Update, context: ContextTypes.DEFAULT_TYPE):
    selected = update.message.text
    bills = context.user_data.get('bills', [])
    chat_id = str(update.message.chat_id)
    
    if selected == 'انصراف':
        await update.message.reply_text(
            "عملیات لغو شد.", 
            reply_markup=get_menu_markup(chat_id)
        )
        return ConversationHandler.END
    
    selected_bill = None
    for bill in bills:
        if f"{bill['bill_title']} ({bill['bill_identifier']})" == selected:
            selected_bill = bill
            break
    
    if not selected_bill:
        keyboard = [[f"{bill['bill_title']} ({bill['bill_identifier']})"] for bill in bills] + [['انصراف']]
        await update.message.reply_text(
            "⚠️ قبض نامعتبر! لطفاً دوباره انتخاب کنید:",
            reply_markup=ReplyKeyboardMarkup(keyboard, resize_keyboard=True)
        )
        return SELECT_BILL
    
    user_data[chat_id] = {
        'mobile': context.user_data['mobile'],
        'token': context.user_data['token'],
        'bill_id': selected_bill['bill_identifier'],
        'bill_title': selected_bill['bill_title']
    }
    save_user_data(user_data)
    
    await update.message.reply_text(
        f"✅ عضویت تکمیل شد!\n"
        f"📌 قبض: {selected_bill['bill_title']}\n"
        f"🔢 شماره: {selected_bill['bill_identifier']}",
        reply_markup=get_menu_markup(chat_id)
    )
    return ConversationHandler.END
    

# --- لغو گفتگو ---
async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = str(update.message.chat_id)  # دریافت chat_id
    await update.message.reply_text(
        "عملیات لغو شد.", 
        reply_markup=get_menu_markup(chat_id)  # استفاده از تابع get_menu_markup
    )
    return ConversationHandler.END
# --- حذف دیتا---
async def delete_account(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = str(update.message.chat_id)
    
    if chat_id in user_data:
        keyboard = [["✔️ تأیید حذف", "❎ انصراف"]]
        reply_markup = ReplyKeyboardMarkup(keyboard, resize_keyboard=True)
        
        await update.message.reply_text(
            "⚠️ با حذف عضویت:\n"
            "- کلیه داده‌های شما پاک می‌شود\n"
            "- اطلاع‌رسانی‌های آینده متوقف می‌شود\n\n"
            "آیا مطمئن هستید؟",
            reply_markup=reply_markup
        )
        return "CONFIRM_DELETION"
    else:
        await update.message.reply_text(
            "شما هنوز عضویتی ندارید.",
            reply_markup=get_menu_markup(chat_id)  # تغییر اینجا
        )
        return ConversationHandler.END
    
# --- تایید حذف ---
async def confirm_deletion(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = str(update.message.chat_id)
    user_choice = update.message.text
    
    if user_choice == "✔️ تأیید حذف":
        if chat_id in user_data:
            mobile = user_data[chat_id]['mobile']
            del user_data[chat_id]
            save_user_data(user_data)
            await update.message.reply_text(
                f"✅ عضویت با شماره {mobile} حذف شد.\n"
                f"اکنون می‌توانید مجدداً ثبت نام کنید.",
                reply_markup=get_menu_markup(chat_id)
            )
    else:
        await update.message.reply_text(
            "عملیات حذف لغو شد.",
            reply_markup=get_menu_markup(chat_id)
        )
    
    return ConversationHandler.END

# --- هندلر منوی اصلی ---
async def handle_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text
    chat_id = str(update.message.chat_id)

    if text == "✅ عضویت جهت اطلاع‌رسانی":
        await start_registration(update, context)
    elif text == "📊 بررسی وضعیت خاموشی":
        await check_blackouts(update, context)
    elif text == "❌ حذف عضویت":
        await delete_account(update, context)

async def setup_scheduler(application: Application):
    """تنظیم زمان‌بندی بررسی خودکار"""
    job_queue = application.job_queue
    if job_queue:
        tehran_tz = pytz.timezone('Asia/Tehran')
        
        # زمان‌بندی اصلی (8 صبح)
        target_time = time(hour=00, minute=22, tzinfo=tehran_tz)
        job_queue.run_daily(
            callback=check_and_notify,
            time=target_time,
            name="daily_blackout_check",
            job_kwargs={'misfire_grace_time': 3600}
        )
        logger.info("⏰ زمان‌بندی بررسی روزانه تنظیم شد (8 صبح)")
        
        # تست فوری - 1 دقیقه بعد از راه‌اندازی
        job_queue.run_once(
            callback=lambda ctx: logger.info("✅ تست زمان‌بندی موفق بود!"),
            when=60,
            name="test_scheduler"
        )
    else:
        logger.error("❌ Job queue در دسترس نیست!")
        # راه‌حل جایگزین با asyncio
        asyncio.create_task(manual_scheduler(application))

async def manual_scheduler(application: Application):
    """راه‌حل جایگزین زمانی که Job Queue کار نمی‌کند"""
    while True:
        tehran_tz = pytz.timezone('Asia/Tehran')
        now = datetime.now(tehran_tz)
        
        if now.hour == 8 and now.minute == 0:
            await check_and_notify(application)
            await asyncio.sleep(60)  # حداقل 1 دقیقه قبل از چک مجدد
        else:
            await asyncio.sleep(30)  # هر 30 ثانیه چک کند

# --- تنظیمات اصلی ربات ---
def main():
    app = ApplicationBuilder().token(TOKEN).build()
    
    # تنظیم هندلرها
    app.add_error_handler(error_handler)

    conv_handler = ConversationHandler(
        entry_points=[MessageHandler(filters.Regex("^✅ عضویت جهت اطلاع‌رسانی$"), start_registration)],
        states={
            GET_MOBILE: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_mobile)],
            GET_OTP: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_otp)],
            SELECT_BILL: [MessageHandler(filters.TEXT & ~filters.COMMAND, select_bill)],
            "CONFIRM_DELETION": [MessageHandler(filters.TEXT & ~filters.COMMAND, confirm_deletion)],
        },
        fallbacks=[CommandHandler('cancel', cancel)],
        allow_reentry=True
    )

    deletion_handler = ConversationHandler(
        entry_points=[MessageHandler(filters.Regex("^❌ حذف عضویت$"), delete_account)],
        states={
            "CONFIRM_DELETION": [MessageHandler(filters.TEXT & ~filters.COMMAND, confirm_deletion)],
        },
        fallbacks=[CommandHandler('cancel', cancel)],
    )

    # اضافه کردن هندلرها
    app.add_handler(CommandHandler("start", start))
    app.add_handler(conv_handler)
    app.add_handler(deletion_handler)
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_menu))

    # راه‌حل جایگزین برای زمان‌بندی
    async def post_init(application: Application):
        """تابعی که بعد از راه‌اندازی اجرا می‌شود"""
        await setup_scheduler(application)

    # اجرای ربات با زمان‌بندی
    loop = asyncio.get_event_loop()
    loop.run_until_complete(post_init(app))
    app.run_polling()

    logger.info("✅ ربات شروع به کار کرد")


if __name__ == "__main__":
    main()