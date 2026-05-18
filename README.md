# VirusTotal Telegram Bot

Telegram-бот, який надсилає файли на перевірку в [VirusTotal](https://www.virustotal.com/) і повертає результат у чат.

Стек: Java 17, [telegrambots](https://github.com/rubenlagus/TelegramBots), Docker. Можна підняти на Render (background worker) або на своєму VPS.

## Що вміє

- приймає файл у Telegram і відправляє його в VirusTotal;
- повертає підсумок сканування (скільки движків спрацювало);
- обмежує розмір файлу через `MAX_FILE_SIZE_MB`.

## Стек

| | |
|---|---|
| Мова | Java 17 |
| Збірка | Maven (`maven-shade-plugin` → fat JAR) |
| Telegram | `org.telegram:telegrambots` 6.9.7.1 |
| HTTP | OkHttp 3 |
| JSON | Gson |
| Логи | SLF4J + Logback |
| Деплой | Docker (Alpine), опційно `render.yaml` |

## Швидкий старт

### Локально

1. Клонуйте репозиторій.
2. Створіть `.env` у корені (файл у `.gitignore`):

```env
BOT_TOKEN=your_telegram_bot_token
BOT_USERNAME=your_bot_username
VIRUSTOTAL_API_KEY=your_virustotal_api_key
MAX_FILE_SIZE_MB=32
