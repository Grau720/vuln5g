FROM python:3.10-slim

# Evitar interactividad
ENV DEBIAN_FRONTEND=noninteractive

# Actualizar e instalar dependencias necesarias para compilar XGBoost
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    && rm -rf /var/lib/apt/lists/*

# Crear directorio de trabajo
WORKDIR /app

# Copiar requirements del módulo IA
COPY requirements-ia.txt /app/requirements-ia.txt

# Instalar dependencias
RUN pip install --upgrade pip && \
    pip install -r requirements-ia.txt

# Copiar el código del módulo IA
COPY services/ia/ /app/ia/

# Para desarrollo, dejamos el contenedor en modo shell
CMD ["/bin/bash"]
