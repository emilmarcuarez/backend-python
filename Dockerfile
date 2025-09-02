# Imagen base oficial de Playwright con Python + navegadores
FROM mcr.microsoft.com/playwright/python:v1.45.0-jammy

# Variables de entorno recomendadas
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    XDG_CACHE_HOME=/tmp/.cache

# Directorio de trabajo en el contenedor
WORKDIR /app

# Copiar dependencias
COPY requirements.txt /app/requirements.txt
RUN pip install --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt

# Copiar el resto del código
COPY . /app

# Exponer puerto de Gunicorn
EXPOSE 8000

# Arranque de la app
CMD ["gunicorn", "app_flask:app", "--bind", "0.0.0.0:8000", "--workers", "1", "--worker-class", "sync", "--timeout", "120", "--keep-alive", "5", "--max-requests", "1000", "--max-requests-jitter", "100", "--preload"]
