# Правила

## Реєстри правил

Правила групуються за реєстром (наприклад, `web`, `fingerprints` або віддалені реєстри). Джерелом результату завжди є назва реєстру.

## Схема правил

Поля YAML-документа правила:
- `id` (рядок, унікальний)
- `title` (рядок)
- `description` (рядок)
- `category` (рядок)
- `severity` (`critical|high|medium|low|info`)
- `confidence_base` (0-100)
- об'єкт `match` (`type` та специфічні для зіставлення поля)
- `recommendation` (рядок)

Опціональні поля: `cwe`, `tags`, `payloads`, `references`, `safe`, `enabled`.

Підтримувані зіставлення: `contains_any`, `contains_all`, `regex`, `reflected_without_encoding`, `missing_header`, `insecure_cookie`, `status_code_changed`, `response_length_delta`, `server_error`, `technology_detected`.

## Створення користувацького правила (крок за кроком)

1. Оберіть папку реєстру.
- Локально: помістіть файл у `rules/<registry>/`.
- Приклад: `rules/web/my_custom_rule.yaml`.

2. Створіть YAML-правило.

```yaml
id: XSS_REFLECTED_CUSTOM_001
title: Маркер відображеного XSS у відповіді
description: Корисне навантаження відображається без кодування виводу.
category: xss
severity: high
confidence_base: 85
match:
  type: reflected_without_encoding
recommendation: Кодуйте вивід та використовуйте суворе екранування шаблонів.
safe: true
enabled: true
```

3. Валідація.
- Запустіть `vulnscope doctor`.
- Завантажувач перевіряє схему та дублікати ID.

4. Запустіть сканування та перевірте джерело.
- Запустіть сканування в TUI.
- Результати з цього файлу покажуть джерело, що дорівнює реєстру (`web` у цьому прикладі).

## Віддалена стрічка правил

Використовуйте `vulnscope serve` у робочому просторі, що має каталог `rules/`.

```bash
vulnscope serve --ip 127.0.0.1 --port 8080
vulnscope serve --path ./rules
```

Кінцеві точки стрічки:
- `/` JSON-індекс, коли `Accept: application/json`.
- `/` стилізований HTML-індекс із пошуком в іншому випадку.
- `/rules/<registry>/<file>.yaml` сирий YAML для машинних клієнтів, стилізований HTML для браузерних клієнтів.

Метадані хешу стрічки:
- Індекс включає `feed_hash` для всього вмісту стрічки.
- Кожен запис правила включає `hash` для вмісту правила.
- Кеш клієнта спочатку порівнює `feed_hash`; якщо він змінився, він порівнює `hash` кожного правила та завантажує лише змінені правила.

## Вибір віддаленої стрічки

На екрані Нового сканування:
- локальні та віддалені стрічки відображаються в спільному ієрархічному дереві,
- віддалені стрічки завантажуються за запитом,
- кожен елемент дерева можна перемкнути для вибору правил для конкретного сканування.

Структура кешу:
- `~/.vulnscope/cache/remote-feeds/{encoded_url}/index.json`
- `~/.vulnscope/cache/remote-feeds/{encoded_url}/rules/...`