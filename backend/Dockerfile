FROM ubuntu:22.04

# Установка необходимых пакетов
RUN apt-get update && apt-get install -y \
    build-essential \
    g++ \
    libpq-dev \
    libssl-dev \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Установка рабочей директории
WORKDIR /app

# Копирование исходного кода
COPY main.cpp .

# Компиляция программы
RUN g++ -std=c++17 -o main main.cpp -lpq -pthread -lcrypto

# Открытие порта
EXPOSE 8080

# Запуск приложения
CMD ["./main"]

