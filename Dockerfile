# استفاده از تصویر پایه پایتون
FROM python:3.11-slim as builder

# تنظیم متغیرهای محیطی
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# نصب وابستگی‌های سیستم
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# کپی فایل‌های مورد نیاز
COPY requirements.txt .

# نصب وابستگی‌های پایتون
RUN pip wheel --no-cache-dir --no-deps --wheel-dir /app/wheels -r requirements.txt

# مرحله نهایی
FROM python:3.11-slim

# ایجاد کاربر غیر root
RUN useradd -m -u 1000 appuser && \
    mkdir -p /app && \
    chown -R appuser:appuser /app

# تنظیم دایرکتوری کاری
WORKDIR /app

# کپی فایل‌های پروژه و wheels از مرحله builder
COPY --from=builder /app/wheels /wheels
COPY --from=builder requirements.txt .
COPY --chown=appuser:appuser . .

# نصب وابستگی‌ها از wheels
RUN pip install --no-cache /wheels/* && \
    rm -rf /wheels

# تغییر کاربر به appuser
USER appuser

# اجرای ربات
CMD ["python", "bot_test_p.py"] 