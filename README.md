# BIP_Individual

# ImageSigner - Програма для криптографічного підпису зображень

## Технічні характеристики

### Криптографічні компоненти
- **RSA-шифрування**: Використовується для створення асиметричних пар ключів (за замовчуванням 4096 біт)
- **Хешування**: SHA-256 для створення хешу даних зображення
- **AES-256 шифрування**: Для додаткового захисту підпису перед вбудовуванням
- **Режим CFB (Cipher Feedback)**: Використовується для AES-шифрування

### Технологія стеганографії
- **Метод LSB**: Модифікація найменш значущих бітів пікселів зображення
- **Псевдовипадкова карта вбудовування**: Визначає розміщення бітів для покращення безпеки
- **Кілька каналів кольору**: Вбудовування даних у канали R, G і B
- **Маркер префіксу довжини**: Забезпечує надійне видобування даних

### Процес підписування
1. Обчислення SHA-256 хешу зображення (без LSB)
2. Створення цифрового підпису за допомогою приватного ключа RSA
3. Шифрування підпису за допомогою AES-256
4. Визначення псевдовипадкових координат для вбудовування
5. Вбудовування зашифрованих даних у LSB пікселів
6. Збереження підписаного зображення у форматі PNG

### Процес перевірки
1. Видобування вбудованих даних із пікселів зображення
2. Розшифрування підпису за допомогою AES
3. Обчислення SHA-256 хешу зображення (без LSB)
4. Перевірка підпису за допомогою публічного ключа RSA

## Вимоги

- Python 3.6 або новіше
- Залежності:
  - cryptography
  - Pillow (PIL)
  - numpy
  - argparse

## Встановлення

```bash
# Клонування репозиторію
git clone https://github.com/username/imagesigner.git
cd imagesigner

# Встановлення залежностей
pip install -r requirements.txt
```
## Використання

### Генерація ключів RSA

```bash
python task.py generate-keys [параметри]
```

**Параметри:**
- `-s, --size` - Розмір ключа в бітах (за замовчуванням: 4096)
- `-o, --output` - Каталог для зберігання ключів (за замовчуванням: "./keys")
- `-p, --password` - Пароль для шифрування приватного ключа (необов'язково)

**Приклад:**
```bash
python imagesigner.py generate-keys -s 4096 -o ./my_keys -p mysecretpassword
```

### Підписування зображення

```bash
python task.py sign [параметри]
```

**Параметри:**
- `-i, --image` - Шлях до зображення для підпису
- `-k, --key` - Шлях до приватного ключа
- `-o, --output` - Шлях для збереження підписаного зображення (необов'язково)
- `-p, --password` - Пароль для розшифрування приватного ключа (якщо застосовується)

**Приклад:**
```bash
python task.py sign -i my_photo.jpg -k ./keys/private_key.pem -o signed_photo.png -p mysecretpassword
```

### Перевірка підпису зображення

```bash
python task.py verify [параметри]
```

**Параметри:**
- `-i, --image` - Шлях до підписаного зображення
- `-k, --key` - Шлях до публічного ключа

**Приклад:**
```bash
python task.py verify -i signed_photo.png -k ./keys/public_key.pem
```

## Конкретний пркилад використання

Для того щоб працювати з конкретним прикладом im1.png та im1_signed.png потірбно зробити наступне:

```bash
python task.py verify -i im1_signed.png -k ./keys/public_key.pem
```

Як результат  програма видає

```
Extracting embedded data...
Extracted length prefix: 560 bytes
Extracted encrypted signature: 560 bytes
Decrypted signature: 512 bytes
Signature verification successful!
```

## Результати виконання команд

### Генерація ключів
```
Generating 4096-bit RSA key pair, please wait...
Key generation completed in 5.67 seconds.
Private key saved to: ./keys/private_key.pem
Public key saved to: ./keys/public_key.pem
```

### Підписування зображення
```
Image hash computed: 32 bytes
Generated signature: 512 bytes
Encrypted signature: 560 bytes
Embedding 4480 bits (560 bytes) using 1494 pixel coordinates
Successfully embedded all 4480 bits
Signed image saved to: signed_photo.png
```

### Перевірка підпису
```
Extracting embedded data...
Extracted length prefix: 560 bytes
Extracted encrypted signature: 560 bytes
Decrypted signature: 512 bytes
Signature verification successful!
```

## Технічні деталі реалізації

### Клас RSAKeyGenerator
Відповідає за генерацію та керування RSA-ключами:
- Генерація пар ключів
- Збереження ключів у PEM-форматі
- Завантаження ключів із файлів
- Шифрування приватних ключів паролем

### Клас ImageSigner
Реалізує функціональність підпису зображення:
- Обчислення хешу зображення
- Створення та перевірка цифрових підписів
- Шифрування та розшифрування підписаних даних
- Вбудовування та вилучення даних із зображення