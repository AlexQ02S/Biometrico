# Usamos una imagen base oficial de Python ligera en Linux Debian
FROM python:3.10-slim

# Evita que Python escriba archivos .pyc en disco y desactiva el buffering de logs
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Instalar dependencias del sistema requeridas para OpenCV, dlib y CMake
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    libopenblas-dev \
    liblapack-dev \
    libx11-dev \
    libgtk-3-dev \
    libgl1-mesa-glx \
    libglib2.0-0 \
    git \
    && rm -rf /var/lib/apt/lists/*

# Definir el directorio de trabajo dentro del contenedor
WORKDIR /app

# Copiar el archivo de requerimientos e instalar las librerías de Python
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copiar todo el código fuente del proyecto al contenedor
COPY . .

# Exponer el puerto por el que correrá Flask (por defecto 5000)
EXPOSE 5000

# Comando para arrancar la aplicación Flask
CMD ["python", "app.py"]