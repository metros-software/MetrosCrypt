# Файловый Энкриптор
![image](https://github.com/user-attachments/assets/d938af79-d7a7-46e2-91da-6ab598513d78)


Многофункциональное приложение для шифрования и дешифрования файлов с расширенным пользовательским интерфейсом на PyQt5.

## Возможности

- **Множество алгоритмов шифрования:**
  - Symmetric: Fernet, AES, 3DES, Blowfish, AES-CBC, CAST, DES, ARC4
  - Stream: ChaCha20, Salsa20
  - Asymmetric: RSA
  - Hash: SHA256, SHA512, MD5, RIPEMD160, SHA1, SHA3_256, SHA3_512
  - KDF: PBKDF2, bcrypt, scrypt
  - Другие: HMAC, zlib (сжатие)

- **Расширенный интерфейс:**
  - Встроенный файловый менеджер
  - Текстовый редактор
  - Встроенный терминал
  - Поддержка тем (светлая/темная)
  - Панель избранного
  - История операций
  - Вкладки для работы с несколькими файлами

- **Особенности:**
  - Пакетное шифрование нескольких файлов
  - Система плагинов для добавления дополнительных методов шифрования
  - Многопоточная обработка для сохранения отзывчивости интерфейса
  - Индикаторы прогресса для длительных операций
  - Возможность добавления папок и файлов в избранное

## Установка

1. Убедитесь, что у вас установлен Python 3.7 или выше
2. Установите зависимости:
```bash
pip install -r requirements.txt
```

## Запуск приложения

```bash
python file_encryptor.py
```

## Использование

### Основные операции шифрования

1. Выберите файл через встроенный файловый менеджер или кнопку "Browse"
2. Выберите метод шифрования из выпадающего списка
3. Введите ключ шифрования (и подтверждение, если требуется)
4. Нажмите "Encrypt" для шифрования или "Decrypt" для дешифрования

### Пакетное шифрование

1. Перейдите на вкладку "Batch Processing"
2. Добавьте несколько файлов через кнопку "Add Files" 
3. Выберите метод шифрования и введите ключ
4. Нажмите "Start Batch Processing"

### Работа с файловым менеджером

- Двойной клик на файле открывает его в редакторе
- Правый клик на файле/папке открывает контекстное меню
- Можно добавлять файлы и папки в избранное для быстрого доступа
- Поддерживается фильтрация и поиск файлов

### Работа с плагинами

1. Перейдите в раздел "Plugins"
2. Просматривайте, добавляйте, редактируйте или удаляйте плагины шифрования
3. Активированные плагины автоматически появятся в списке методов шифрования

## Структура приложения

- `file_encryptor.py` - основной файл приложения
- `resource/assets/` - иконки и ресурсы интерфейса
- `plugins/` - директория для плагинов шифрования
- `data/` - директория для сохранения настроек и истории
- `pem/` - директория для хранения ключей RSA

## Безопасность

- Ключи шифрования не сохраняются в приложении
- Используются проверенные криптографические библиотеки
- Для дешифрования необходимо использовать тот же метод и ключ, которые использовались при шифровании
- При работе с RSA рекомендуется сохранять ключи в безопасном месте

## Примечания

- Зашифрованные файлы сохраняются с расширением .encrypted
- Расшифрованные файлы сохраняются с расширением .decrypted
- При использовании плагинов убедитесь, что они не содержат вредоносного кода

## Требования

- Python 3.7+
- PyQt5 5.15.9
- cryptography 41.0.3
- pycryptodome 3.19.0
- pycryptodomex 3.19.0
- pyAesCrypt 6.0.0 
