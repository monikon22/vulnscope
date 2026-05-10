# Конфігурація

Пріоритет конфігурації:
1. `VULNSCOPE_CONFIG`
2. `./vulnscope.yaml`
3. `~/.config/vulnscope/vulnscope.yaml`

## Змінні оточення

- `VULNSCOPE_CONFIG`: абсолютний або відносний шлях до YAML-файлу конфігурації.
- `VULNSCOPE_DATABASE_PATH`: перевизначення для `app.database_path`.
- `VULNSCOPE_REPORT_DIR`: перевизначення для `app.report_dir` та `export.report_dir`.
- `VULNSCOPE_RATE_LIMIT`: перевизначення для `scanner.rate_limit`.

## Повна YAML-схема

### `app`
- `database_path` (рядок, за замовчуванням `./data/vulnscope.db`): шлях до бази даних SQLite.
- `report_dir` (рядок, за замовчуванням `./reports`): каталог звітів (базове значення).

### `scanner`
- `default_profile` (рядок, за замовчуванням `default`): ім'я профілю сканування за замовчуванням.
- `rate_limit` (float, за замовчуванням `5.0`): запитів за секунду.
- `timeout` (float, за замовчуванням `10.0`): таймаут HTTP-запиту.
- `max_depth` (int, за замовчуванням `2`): глибина обходу BFS.
- `max_pages` (int, за замовчуванням `50`): макс. кількість сторінок за сканування.
- `user_agent` (рядок, за замовчуванням `VulnScope/0.1`): user agent, що використовується HTTP-клієнтом.

### `rules`
- `paths` (список[рядок], за замовчуванням `['./rules/web']`): локальні шляхи до YAML-файлів/каталогів правил.
- `enabled_categories` (список[рядок], за замовчуванням `[]`): фільтр категорій за замовчуванням.
- `enabled_registries` (список[рядок], за замовчуванням `[]`): фільтр реєстрів за замовчуванням.
- `remote_feeds` (список[рядок], за замовчуванням `[]`): список URL-адрес віддалених стрічок правил.
- `remote_cache_dir` (рядок|null, за замовчуванням `null`): кореневий каталог для кешу віддалених стрічок.
  Якщо `null`, використовується `~/.vulnscope/cache/remote-feeds`.

### `export`
- `default_format` (рядок, за замовчуванням `html`): формат експорту за замовчуванням (`html|json|markdown`).
- `report_dir` (рядок, за замовчуванням `./reports`): каталог вихідних звітів.
- `include_http_evidence` (bool, за замовчуванням `true`): прапорець сумісності, що зберігається в конфігурації для використання в UI/експорті.
- `include_response_bodies` (bool, за замовчуванням `false`): прапорець, що використовується для сценаріїв обрізання тіла JSON-експорту.
- `json_pretty` (bool, за замовчуванням `true`): гарний друк JSON (`indent=2`).
- `html_theme` (рядок, за замовчуванням `dark`): тема HTML-звіту (`dark|light|academic`).

### `profiles`

Мапа визначених користувачем профілів сканування:

`profiles.<name>`:
- `rate_limit` (float, за замовчуванням `5.0`)
- `max_depth` (int, за замовчуванням `2`)
- `max_pages` (int, за замовчуванням `50`)
- `enabled_registries` (список[рядок], за замовчуванням `[]`)
- `enabled_categories` (список[рядок], за замовчуванням `[]`)
- `enabled_rule_ids` (список[рядок], за замовчуванням `[]`)
- `enabled_rule_refs` (список[рядок], за замовчуванням `[]`, формат `source::rule_id`)
- `remote_feeds` (список[рядок], за замовчуванням `[]`)

## ScanConfig під час виконання (ефективний, для кожного сканування)

На додаток до налаштувань YAML, для кожного запуску сканування створюється ефективний `ScanConfig`:

- `target.url`
- `target.scope_mode` (`same_host|same_domain|custom`)
- `target.include_patterns` / `target.exclude_patterns`
- `profile`
- `rate_limit`, `timeout`, `max_depth`, `max_pages`, `user_agent`
- `dependency_audit`
- `auth_headers`
- `enabled_registries`, `enabled_categories`, `enabled_rule_ids`, `enabled_rule_refs`
- `remote_feeds`

Ці поля серіалізуються в `scan.metadata.config` і відображаються в деталях сканування (Scan Detail).

## Повний приклад

```yaml
app:
	database_path: ./data/vulnscope.db
	report_dir: ./reports

scanner:
	default_profile: default
	rate_limit: 5
	timeout: 10
	max_depth: 2
	max_pages: 50
	user_agent: "VulnScope/0.1"

rules:
	paths:
		- ./rules/web
		- ./rules/fingerprints
	enabled_categories: []
	enabled_registries: []
	remote_feeds:
		- http://127.0.0.1:8080
	remote_cache_dir: null

profiles: