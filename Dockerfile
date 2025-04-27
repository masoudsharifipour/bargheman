# ---- Build stage ----
    FROM python:3.13-alpine AS builder

    ENV PYTHONUNBUFFERED=1 \
        PYTHONDONTWRITEBYTECODE=1 \
        PIP_NO_CACHE_DIR=1
    
    RUN apk update && \
        apk add --no-cache gcc musl-dev python3-dev
    
    WORKDIR /app
    
    COPY requirements.txt .
    
    RUN pip wheel --no-cache-dir --no-deps --wheel-dir /wheels -r requirements.txt
    
    # ---- Final stage ----
    FROM python:3.13-alpine
    
    ENV PYTHONUNBUFFERED=1 \
        TZ=Asia/Tehran
    
    RUN apk update && \
        apk add --no-cache tzdata
    
    RUN adduser -D -u 1000 appuser
    
    WORKDIR /app
    
    COPY --from=builder /wheels /wheels
    COPY --from=builder /app/requirements.txt .
    COPY . .
    
    RUN pip install --no-cache-dir /wheels/* && rm -rf /wheels
    
    RUN chown -R appuser:appuser /app
    
    USER appuser
    
    CMD ["python", "bot_test_p.py"]