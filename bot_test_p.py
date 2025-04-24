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

# --- تنظیمات امنیتی ---
MAX_RETRIES = 3
MOBILE_PATTERN = r'^09[0-9]{9}$'
OTP_PATTERN = r'^\d{6}$'

# --- تنظیمات Rate Limiting ---
RATE_LIMIT = {
    'daily_limit': 5,
    'window_hours': 24
}
user_rate_limits = {}  # ذخیره وضعیت Rate Limit کاربران
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

# --- مدیریت Rate Limiting ---


def check_rate_limit(chat_id: str) -> tuple:
    """بررسی Rate Limit برای کاربر"""
    now = datetime.now()
    chat_id = str(chat_id)

    if chat_id not in user_rate_limits:
        # کاربر جدید، محدودیتی ندارد
        user_rate_limits[chat_id] = {
            'count': 1,
            'first_request': now,
            'last_request': now
        }
        return True, RATE_LIMIT['daily_limit'] - 1, None

    user_limit = user_rate_limits[chat_id]
    time_diff = (now - user_limit['first_request']
                 ).total_seconds() / 3600  # به ساعت

    if time_diff > RATE_LIMIT['window_hours']:
        # بازه زمانی جدید، ریست محدودیت
        user_rate_limits[chat_id] = {
            'count': 1,
            'first_request': now,
            'last_request': now
        }
        return True, RATE_LIMIT['daily_limit'] - 1, None

    if user_limit['count'] >= RATE_LIMIT['daily_limit']:
        # کاربر به محدودیت رسیده
        reset_time = user_limit['first_request'] + \
            timedelta(hours=RATE_LIMIT['window_hours'])
        return False, 0, reset_time

    # افزایش تعداد درخواست‌ها
    user_rate_limits[chat_id]['count'] += 1
    remaining = RATE_LIMIT['daily_limit'] - user_rate_limits[chat_id]['count']
    return True, remaining, None


async def reset_daily_limits(context: ContextTypes.DEFAULT_TYPE):
    """ریست روزانه محدودیت‌های کاربران"""
    global user_rate_limits
    logger.info("♻️ ریست روزانه محدودیت‌های درخواست کاربران")
    user_rate_limits = {}

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
    logger.error(msg="Exception while handling an update:",
                 exc_info=context.error)
    if update and isinstance(update, Update):
        try:
            await update.message.reply_text("⚠️ خطایی رخ داد. لطفاً دوباره تلاش کنید.")
        except:
            pass

# --- توابع رمزنگاری ---


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
    url = "http://halalabad.ir/proxy.php/send-otp"
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "origin": "https://ios.bargheman.com",
        "referer": "https://ios.bargheman.com/",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    }
    payload = {"mobile": mobile}

    try:
        response = requests.post(url, headers=headers,
                                 json=payload, timeout=60)
        response.raise_for_status()
        logger.info(f"OTP sending response {response.json}")
        return response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"Error sending OTP: {str(e)}")
        return None


async def verify_otp(mobile: str, code: str):
    url = "http://halalabad.ir/proxy.php/verify-otp"
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
        response = requests.post(url, headers=headers,
                                 json=payload, timeout=60)
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
    url = "http://halalabad.ir/proxy.php/get-user-bills"
    headers = {
        "accept": "application/json",
        "authorization": f"Bearer {auth_token}",
        "content-type": "application/json",
        "origin": "https://ios.bargheman.com",
        "referer": "https://ios.bargheman.com/",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    }

    try:
        # ابتدا با GET امتحان می‌کنیم
        response = requests.get(url, headers=headers, timeout=50)

        # اگر خطای 405 داد، با POST امتحان می‌کنیم
        if response.status_code == 405:
            response = requests.post(url, headers=headers, json={}, timeout=50)

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

            result = await get_blackouts(user_info['token'], user_info['bill_id'])

            if not result:
                # اگر نتیجه خالی بود، پیام مناسب ارسال شود
                DATE, TO_DATE = get_jalali_dates()  # دریافت تاریخ‌های جاری
                message = (
                    f"🔍 بررسی خودکار برای بازه {DATE} تا {TO_DATE}\n"
                    "✅ هیچ خاموشی (قطع برق) برنامه‌ریزی شده یا رخ داده‌ای یافت نشد."
                )
                await context.bot.send_message(
                    chat_id=chat_id,
                    text=message,
                    disable_notification=False
                )
                continue

            message = f"⚠️ هشدار خاموشی برای بازه {result['date_range']['from']} تا {result['date_range']['to']}:\n\n"

            if result['occurred']:
                message += "\n🔴 خاموشی‌های رخ داده:\n"
                for i, item in enumerate(result['occurred'], 1):
                    message += (
                        f"{i}. 📅 {item.get('outage_date', '?')} "
                        f"⏰ {item.get('outage_start_time', '?')}-{item.get('outage_stop_time', '?')}\n"
                        f"📍 {item.get('outage_address', '?')}\n\n"
                    )
            else:
                message += "\n🔴 خاموشی‌های رخ داده: موردی یافت نشد\n\n"

            if result['planned']:
                message += "\n🟡 خاموشی‌های برنامه‌ریزی شده:\n"
                for i, item in enumerate(result['planned'], 1):
                    message += (
                        f"{i}. 📅 {item.get('outage_date', '?')} "
                        f"⏰ {item.get('outage_start_time', '?')}-{item.get('outage_stop_time', '?')}\n"
                        f"📍 {item.get('outage_address', '?')}\n\n"
                    )
            else:
                message += "\n🟡 خاموشی‌های برنامه‌ریزی شده: موردی یافت نشد\n\n"

            await context.bot.send_message(
                chat_id=chat_id,
                text=message,
                disable_notification=False
            )

        except Exception as e:
            logger.error(f"Error processing user {chat_id}: {str(e)}")
            # در صورت خطا هم پیام مناسبی ارسال شود
            DATE, TO_DATE = get_jalali_dates()
            error_message = (
                f"⚠️ خطا در بررسی خاموشی‌ها برای بازه {DATE} تا {TO_DATE}\n"
                "لطفاً به صورت دستی بررسی کنید یا بعداً مجدداً تلاش نمایید."
            )
            await context.bot.send_message(
                chat_id=chat_id,
                text=error_message,
                disable_notification=False
            )


async def get_blackouts(token: str, bill_id: str):
    """دریافت لیست خاموشی‌ها از طریق پراکسی"""
    headers = {
        "accept": "application/json",
        "authorization": f"Bearer {token}",
        "content-type": "application/json",
        "origin": "https://ios.bargheman.com",
        "referer": "https://ios.bargheman.com/",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    }

    DATE, TO_DATE = get_jalali_dates()
    logger.info(
        f"Getting blackouts from {DATE} to {TO_DATE} for bill {bill_id}")

    try:
        payload = {
            "bill_id": bill_id,
            "date": DATE,
            "from_date": DATE,
            "to_date": TO_DATE
        }

        response = requests.post(
            "http://halalabad.ir/proxy.php/get-blackouts",
            headers=headers,
            json=payload,
            timeout=60
        )
        response.raise_for_status()

        return response.json()

    except requests.exceptions.Timeout:
        logger.error("Timeout in getting blackouts via proxy")
        return None
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error in getting blackouts via proxy: {str(e)}")
        return None
    except Exception as e:
        logger.error(
            f"Unexpected error in getting blackouts via proxy: {str(e)}", exc_info=True)
        return None


async def check_blackouts(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = str(update.message.chat_id)

    # بررسی Rate Limit (بدون تغییر)
    allowed, remaining, reset_time = check_rate_limit(chat_id)
    if not allowed:
        reset_str = reset_time.strftime(
            "%Y-%m-%d %H:%M:%S") if reset_time else "پس از 24 ساعت"
        await update.message.reply_text(
            f"⚠️ سقف درخواست روزانه ({RATE_LIMIT['daily_limit']}) را رد کرده‌اید.\n"
            f"⏳ لطفاً بعد از {reset_str} دوباره تلاش کنید.",
            reply_markup=get_menu_markup(chat_id)
        )
        return

    user = user_data.get(chat_id, {})
    token = user.get("token")
    bill_id = user.get("bill_id")

    if not token or not bill_id:
        await update.message.reply_text(
            "⚠️ شما هنوز وارد نشده‌اید یا قبضی انتخاب نکرده‌اید.",
            reply_markup=get_menu_markup(chat_id)
        )
        logger.warning("کاربر بدون توکن یا bill_id")
        return

    DATE, TO_DATE = get_jalali_dates()
    logger.info(f"بررسی خاموشی از {DATE} تا {TO_DATE}")

    headers = {
        "accept": "application/json",
        "authorization": f"Bearer {token}",
        "content-type": "application/json",
        "origin": "https://ios.bargheman.com",
        "referer": "https://ios.bargheman.com/",
        "user-agent": "Mozilla/5.0"
    }

    await update.message.reply_text(f"🔍 در حال بررسی خاموشی‌ها از {DATE} تا {TO_DATE}...")

    try:
        # درخواست به پراکسی PHP
        proxy_url = "http://halalabad.ir/proxy.php/check-blackouts"
        payload = {
            "bill_id": bill_id,
            "date": DATE,
            "to_date": TO_DATE
        }

        log_request("Proxy Request", proxy_url, headers, payload, token)

        session = create_session()
        response = session.post(
            proxy_url, headers=headers, json=payload, timeout=60)
        response.raise_for_status()

        result = response.json()
        data1 = result.get("occurred_blackouts", [])
        data2 = result.get("planned_blackouts", [])

        if not data1 and not data2:
            await update.message.reply_text(
                "✅ هیچ خاموشی در بازه موردنظر یافت نشد.",
                reply_markup=get_menu_markup(chat_id)
            )
            return

        msg = format_blackout_message(data1, data2)
        await update.message.reply_text(msg, reply_markup=get_menu_markup(chat_id))

        if remaining is not None and remaining < 3:
            await update.message.reply_text(
                f"ℹ️ فقط {remaining} درخواست باقی مانده تا پایان امروز.",
                reply_markup=get_menu_markup(chat_id)
            )

    except requests.exceptions.Timeout:
        logger.error("⏳ سرور پاسخگو نیست.")
        await update.message.reply_text(
            "⏳ سرور پاسخگو نیست. لطفاً چند دقیقه دیگر تلاش کنید.",
            reply_markup=get_menu_markup(chat_id)
        )
    except requests.exceptions.RequestException as e:
        logger.error(f"❌ خطای ارتباط با سرور: {e}")
        await update.message.reply_text(
            f"❌ خطا در ارتباط با سرور: {str(e)}",
            reply_markup=get_menu_markup(chat_id)
        )
    except Exception as e:
        logger.error("❌ خطای ناشناخته", exc_info=True)
        await update.message.reply_text(
            f"❌ خطای ناشناخته: {str(e)}",
            reply_markup=get_menu_markup(chat_id)
        )


def log_request(label, url, headers, payload, token):
    logger.info(f"[{label}] POST {url}")
    logger.info(f"[{label}] Headers: {headers}")
    logger.info(f"[{label}] Payload: {payload}")
    curl = f"curl -X POST '{url}' -H 'Authorization: Bearer {token}' -H 'Content-Type: application/json' -d '{json.dumps(payload)}'"
    logger.info(f"[{label}] CURL: {curl}")


def format_blackout_message(data1, data2):
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
    return msg

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

    if chat_id in user_data:
        user = user_data[chat_id]
        await update.message.reply_text(
            f"⚠️ شما قبلاً عضو شده‌اید:\n"
            f"📱 شماره: {user['mobile']}\n"
            f"🔹 قبض: {user['bill_title']}\n\n"
            f"برای تغییر اطلاعات، لطفاً ابتدا عضویت خود را حذف کنید.",
            reply_markup=get_menu_markup(chat_id)
        )
        return ConversationHandler.END

    await update.message.reply_text(
        "لطفاً شماره موبایل خود را وارد کنید (مثال: 09123456789):",
        reply_markup=ReplyKeyboardRemove()
    )
    return GET_MOBILE

# --- دریافت شماره موبایل و ارسال OTP ---


async def get_mobile(update: Update, context: ContextTypes.DEFAULT_TYPE):
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
    otp = update.message.text.strip()

    if not validate_otp(otp):
        await update.message.reply_text("⚠️ کد تایید نامعتبر است. لطفاً کد 6 رقمی را به درستی وارد کنید.")
        return GET_OTP

    try:
        mobile = context.user_data.get('mobile')
        if not mobile:
            raise ValueError("شماره موبایل یافت نشد")

        # تایید OTP
        result = await safe_api_call(verify_otp, mobile, otp)
        if not result or not result.get('data', {}).get('Token'):
            await update.message.reply_text("❌ کد تایید نامعتبر است. لطفاً دوباره تلاش کنید.")
            return GET_OTP

        token = result['data']['Token']
        context.user_data['token'] = token

        await update.message.reply_text("⏳ در حال دریافت قبض‌ها...")

        # دریافت قبض‌ها با مدیریت خطاهای بهتر
        try:
            bills_response = await get_user_bills(token)

            if not bills_response:
                raise ValueError("پاسخی از سرور دریافت نشد")

            # بررسی ساختارهای مختلف پاسخ
            bills = []
            if isinstance(bills_response, dict):
                if 'data' in bills_response and 'bill_data' in bills_response['data']:
                    bills = bills_response['data']['bill_data']
                elif 'data' in bills_response:
                    bills = bills_response['data']
            elif isinstance(bills_response, list):
                bills = bills_response

            if not bills:
                await update.message.reply_text(
                    "⚠️ هیچ قبضی یافت نشد. لطفاً به سامانه مراجعه کنید.",
                    reply_markup=get_menu_markup(str(update.message.chat_id)))
                return ConversationHandler.END

            context.user_data['bills']=bills
            keyboard=[
                [f"{bill.get('bill_title', 'بدون عنوان')} ({bill.get('bill_identifier', '')})"]
                for bill in bills
            ]
            keyboard.append(['انصراف'])

            await update.message.reply_text(
                "لطفاً قبض مورد نظر را انتخاب کنید:",
                reply_markup=ReplyKeyboardMarkup(
                    keyboard, resize_keyboard=True)
            )
            return SELECT_BILL

        except Exception as e:
            logger.error(f"Error in bills retrieval: {str(e)}")
            await update.message.reply_text("❌ خطا در دریافت قبض‌ها. لطفاً بعداً تلاش کنید.")
            return ConversationHandler.END

    except Exception as e:
        logger.error(f"Unexpected error in get_otp: {str(e)}", exc_info=True)
        await update.message.reply_text("❌ خطای غیرمنتظره رخ داده است. لطفاً بعداً تلاش کنید.")
        return ConversationHandler.END

# --- انتخاب قبض و تکمیل عضویت ---


async def select_bill(update: Update, context: ContextTypes.DEFAULT_TYPE):
    selected=update.message.text
    bills=context.user_data.get('bills', [])
    chat_id=str(update.message.chat_id)

    if selected == 'انصراف':
        await update.message.reply_text(
            "عملیات لغو شد.",
            reply_markup=get_menu_markup(chat_id)
        )
        return ConversationHandler.END

    selected_bill=None
    for bill in bills:
        if f"{bill['bill_title']} ({bill['bill_identifier']})" == selected:
            selected_bill=bill
            break

    if not selected_bill:
        keyboard=[[f"{bill['bill_title']} ({bill['bill_identifier']})"]
                    for bill in bills] + [['انصراف']]
        await update.message.reply_text(
            "⚠️ قبض نامعتبر! لطفاً دوباره انتخاب کنید:",
            reply_markup=ReplyKeyboardMarkup(keyboard, resize_keyboard=True)
        )
        return SELECT_BILL

    user_data[chat_id]={
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
    chat_id=str(update.message.chat_id)
    await update.message.reply_text(
        "عملیات لغو شد.",
        reply_markup=get_menu_markup(chat_id)
    )
    return ConversationHandler.END

# --- حذف دیتا ---


async def delete_account(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id=str(update.message.chat_id)

    if chat_id in user_data:
        keyboard=[["✔️ تأیید حذف", "❎ انصراف"]]
        reply_markup=ReplyKeyboardMarkup(keyboard, resize_keyboard=True)

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
            reply_markup=get_menu_markup(chat_id)
        )
        return ConversationHandler.END

# --- تایید حذف ---


async def confirm_deletion(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id=str(update.message.chat_id)
    user_choice=update.message.text

    if user_choice == "✔️ تأیید حذف":
        if chat_id in user_data:
            mobile=user_data[chat_id]['mobile']
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
    text=update.message.text
    chat_id=str(update.message.chat_id)

    if text == "✅ عضویت جهت اطلاع‌رسانی":
        await start_registration(update, context)
    elif text == "📊 بررسی وضعیت خاموشی":
        allowed, remaining, reset_time=check_rate_limit(chat_id)
        if not allowed:
            reset_str=reset_time.strftime("%Y-%m-%d %H:%M:%S")
            await update.message.reply_text(
                f"⚠️ شما به سقف درخواست‌های روزانه ({RATE_LIMIT['daily_limit']}) رسیده‌اید.\n"
                f"لطفاً پس از {reset_str} دوباره تلاش کنید.",
                reply_markup=get_menu_markup(chat_id))
            return

        await check_blackouts(update, context)
    elif text == "❌ حذف عضویت":
        await delete_account(update, context)


async def setup_scheduler(application: Application):
    """تنظیم زمان‌بندی بررسی خودکار"""
    job_queue=application.job_queue
    if job_queue:
        tehran_tz=pytz.timezone('Asia/Tehran')

        # زمان‌بندی اصلی (10 صبح)
        target_time=time(hour=10, minute=00, tzinfo=tehran_tz)
        job_queue.run_daily(
            callback=check_and_notify,
            time=target_time,
            name="daily_blackout_check",
            job_kwargs={'misfire_grace_time': 3600}
        )

        # ریست روزانه محدودیت‌ها در نیمه شب
        reset_time=time(hour=0, minute=0, tzinfo=tehran_tz)
        job_queue.run_daily(
            callback=reset_daily_limits,
            time=reset_time,
            name="reset_rate_limits"
        )

        logger.info("⏰ زمان‌بندی بررسی روزانه و ریست محدودیت‌ها تنظیم شد")
    else:
        logger.error("❌ Job queue در دسترس نیست!")
        # راه‌حل جایگزین با asyncio
        asyncio.create_task(manual_scheduler(application))


async def manual_scheduler(application: Application):
    """راه‌حل جایگزین زمانی که Job Queue کار نمی‌کند"""
    while True:
        tehran_tz=pytz.timezone('Asia/Tehran')
        now=datetime.now(tehran_tz)

        if now.hour == 8 and now.minute == 0:
            await check_and_notify(application)
            await asyncio.sleep(60)
        elif now.hour == 0 and now.minute == 0:
            await reset_daily_limits(application)
            await asyncio.sleep(60)
        else:
            await asyncio.sleep(30)

# --- تنظیمات اصلی ربات ---


def main():
    app=ApplicationBuilder().token(TOKEN).build()

    # تنظیم هندلرها
    app.add_error_handler(error_handler)

    conv_handler=ConversationHandler(
        entry_points=[MessageHandler(filters.Regex(
            "^✅ عضویت جهت اطلاع‌رسانی$"), start_registration)],
        states={
            GET_MOBILE: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_mobile)],
            GET_OTP: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_otp)],
            SELECT_BILL: [MessageHandler(filters.TEXT & ~filters.COMMAND, select_bill)],
            "CONFIRM_DELETION": [MessageHandler(filters.TEXT & ~filters.COMMAND, confirm_deletion)],
        },
        fallbacks=[CommandHandler('cancel', cancel)],
        allow_reentry=True
    )

    deletion_handler=ConversationHandler(
        entry_points=[MessageHandler(
            filters.Regex("^❌ حذف عضویت$"), delete_account)],
        states={
            "CONFIRM_DELETION": [MessageHandler(filters.TEXT & ~filters.COMMAND, confirm_deletion)],
        },
        fallbacks=[CommandHandler('cancel', cancel)],
    )

    # اضافه کردن هندلرها
    app.add_handler(CommandHandler("start", start))
    app.add_handler(conv_handler)
    app.add_handler(deletion_handler)
    app.add_handler(MessageHandler(
        filters.TEXT & ~filters.COMMAND, handle_menu))

    # اجرای ربات با زمان‌بندی
    async def post_init(application: Application):
        await setup_scheduler(application)

    loop=asyncio.get_event_loop()
    loop.run_until_complete(post_init(app))
    app.run_polling()

    logger.info("✅ ربات شروع به کار کرد")


if __name__ == "__main__":
    main()
