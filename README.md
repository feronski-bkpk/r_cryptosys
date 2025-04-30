# R-Cryptosystem

![Rust](https://img.shields.io/badge/lang-Rust-orange)

## О проекте

Консольная утилита для шифрования/дешифрования файлов и каталогов с возможностью:
- Шифрования отдельных файлов
- Шифрования каталогов
- Дешифрования файлов и каталогов
- Задания пароля
- Указания нового имени для зашифрованного файла
- Интерактивного режима
- Шифрования/дешифрования в одну строку
- Подробного логгирования (verbose)

## Установка

1. Клонируйте репозиторий:
```bash
git clone https://github.com/feronski-bkpk/r_cryptosys.git
cd r-cryptosys
```

2. Соберите проект:
```bash
cargo build --release
```

Исполняемый файл будет создан в
- `target/release/r_cryptosys` (Linux)
- `target/release/r_cryptosys.exe` (Windows)

## Основные команды

### Шифрование файла
```bash
./r_cryptosys encrypt путь/к/файлу
```

### Дешифрование файла
```bash
./r_cryptosys decrypt путь/к/файлу.enc
```

## Параметры

| Параметр         | Описание                           | Пример использования          |
|------------------|------------------------------------|-------------------------------|
| `-p, --password` | Пароль для шифрования              | `-p "мойпароль"`              |
| `-n, --name`     | Новое имя для зашифрованного файла | `-n "новое_имя"`              |
| `-v, --verbose`  | Подробное ведение логов            | `--verbose`                   |

## Полный список команд для Linux

```bash
# Базовое шифрование
./r_cryptosys encrypt file.txt

# Шифрование с паролем
./r_cryptosys encrypt doc.pdf -p "P@ssw0rd"

# Шифрование с новым именем
./r_cryptosys encrypt image.jpg -n "backup"

# Полная команда
./r_cryptosys --verbose encrypt data.db -p "12345" -n "encrypted_db"

# Дешифрование
./r_cryptosys decrypt file.enc

# Дешифрование с паролем
./r_cryptosys decrypt data.enc -p "12345"
```

## Полный список команд для PowerShell

```powershell
# Базовое шифрование
.\r_cryptosys.exe encrypt file.txt

# Шифрование с параметрами
.\r_cryptosys.exe encrypt doc.docx -p "Secret!" -n "encrypted"

# Дешифрование
.\r_cryptosys.exe decrypt encrypted.enc

# С подробным выводом
.\r_cryptosys.exe --verbose decrypt backup.enc -p "P@ssw0rd"
```
