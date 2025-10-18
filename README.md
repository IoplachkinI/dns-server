# DNS Сервер на C++

Простой DNS сервер, написанный на C++, поддерживающий различные типы DNS запросов.

## Возможности

- **A записи** - IPv4 адреса
- **AAAA записи** - IPv6 адреса  
- **CNAME записи** - Канонические имена
- **NS записи** - Серверы имен
- **MX записи** - Почтовые обменники
- **TXT записи** - Текстовые записи
- **PTR записи** - Обратные DNS запросы

## Сборка

### Способ 1: Использование CMake (Рекомендуется)

```bash
# Установка зависимостей (Ubuntu/Debian)
sudo apt install libyaml-cpp-dev cmake build-essential

# Создание директории сборки
mkdir build
cd build

# Конфигурация CMake

cmake -DCMAKE_BUILD_TYPE=Release ..

# Сборка
make -j$(nproc)
```

### Способ 2: Прямая компиляция

```bash
# Установка зависимостей (Ubuntu/Debian)
sudo apt install libyaml-cpp-dev

# Сборка
g++ -o dns_server main.cpp -lyaml-cpp
```

## Использование

```bash
# Справка
./dns_server -h

# Запуск с настройками по умолчанию (порт 53, config.yaml)
sudo ./dns_server

# Запуск с пользовательским конфигом
sudo ./dns_server my_config.yaml

# Запуск с пользовательским портом
sudo ./dns_server my_config.yaml 5454
```

## Конфигурация

DNS записи настраиваются в файле `config.yaml`:

Пример конфига находится в `example.config.yaml`

## Настройка системы

### Способ 1: Отключение systemd-resolved (порт 53)

```bash
# Остановка systemd-resolved
sudo systemctl stop systemd-resolved

# Запуск DNS сервера на порту 53
sudo ./dns_server config.yaml 53

# Тест
dig @localhost example.com A
```

### Способ 2: Использование свободного порта

```bash
# Запуск DNS сервера на свободном порту
sudo ./dns_server config.yaml 5454

# Настройка systemd-resolved
sudo nano /etc/systemd/resolved.conf

# Добавить:
DNS=127.0.0.1:5454
DNSSEC=no

# Перезапуск systemd-resolved
sudo systemctl restart systemd-resolved

# Тест
dig example.com A
```

## Тестирование

```bash
# Тест A записей
dig @127.0.0.1 -p 5454 example.com A

# Тест AAAA записей
dig @127.0.0.1 -p 5454 example.com AAAA

# Тест CNAME записей
dig @127.0.0.1 -p 5454 www.example.com CNAME

# Тест NS записей
dig @127.0.0.1 -p 5454 example.com NS

# Тест MX записей
dig @127.0.0.1 -p 5454 example.com MX

# Тест TXT записей
dig @127.0.0.1 -p 5454 example.com TXT

# Тест PTR записей (обратный DNS)
dig @127.0.0.1 -p 5454 -x 127.0.0.1
```

## Восстановление системы

```bash
# Включение systemd-resolved обратно
sudo systemctl enable systemd-resolved
sudo systemctl start systemd-resolved

# Или восстановление resolv.conf
sudo systemctl restart systemd-resolved
```

## Особенности

- **Память**: Автоматическое управление памятью для DNS записей
- **Производительность**: Обработка запросов в одном потоке
- **Совместимость**: Поддержка стандартных DNS клиентов
- **Гибкость**: Настраиваемые порты и конфигурационные файлы

## Требования

- Linux
- g++ (C++11 или выше)
- libyaml-cpp
- Права root для порта 53

## Лицензия

Этот проект создан в образовательных целях.
