FROM python:3.9-slim

WORKDIR /app

# Sistem paketlerini yükle
RUN apt-get update && apt-get install -y \
    libgmp-dev \
    libmpfr-dev \
    libmpc-dev \
    && rm -rf /var/lib/apt/lists/*

# Python paketlerini yükle
COPY requirements.txt .
RUN pip install -r requirements.txt

# SSL sertifikalarını kopyala
COPY domain.crt domain.crt
COPY domain.key domain.key

# Uygulama kodlarını kopyala
COPY . .

# CORS için origin ayarı
ENV FRONTEND_ORIGIN="https://rsz-frontend.vercel.app"

EXPOSE 5000

# Doğrudan app.py'yi çalıştır
CMD ["python", "app.py"] 