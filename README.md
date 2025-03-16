# AutoFixer

**AutoFixer** – это инструмент для автоматического обнаружения и исправления некоторых распространённых уязвимостей в Python-коде:
- Использование `eval()`
- SQL-инъекции

## Возможности
- **Поиск и исправление eval()**:  
  Скрипт анализирует файлы на наличие вызовов `eval()` и автоматически заменяет их на `ast.literal_eval()` (или иные безопасные аналоги), а также добавляет импорт `ast` при необходимости.

- **Поиск и исправление SQL-инъекций**:  
  Скрипт ищет места, где SQL-запрос формируется путём небезопасной конкатенации строк (например, `"SELECT ... " + str(user_input)`), и переписывает код на параметризованные запросы (например, `cursor.execute(query, (param,))`).


## Установка

### Шаг 1. (Опционально) Создайте и активируйте виртуальное окружение
```bash
python3 -m venv .venv
source .venv/bin/activate
```
### Шаг 2. Установите зависимости
```bash
pip install -r requirements.txt
```
### Шаг 3. Установите пакет
```
pip install .
```
    При установке будет создан(ы) CLI-скрипт(ы) (например, sql-fix, eval-fix) в виртуальном окружении.

## Использование
После установки в активированном окружении будут доступны команды:
- SQL-инъекции:
    - Показать справку(инструкции)
        ```bash
        sql-fix --help 
        ```
    - Поиск уязвимостей
        ```bash
        sql-fix /path/to/your/code
        ```
    - Поиск с автоисправлением
        ```bash
        sql-fix /path/to/your/code --fix
        ```
- eval():
    - Показать справку(инструкции)
        ```bash
        eval-fix --help 
        ```
    - Поиск уязвимостей
        ```bash
        eval-fix /path/to/your/code
        ```
    - Поиск с автоисправлением
        ```bash
        eval-fix /path/to/your/code --fix
        ```
## Структура проекта
```bash
autofixer/
├─ eval_fixer/
│  ├─ __init__.py
│  └─ eval_fixer.py
├─ sql_injection_fixer_v2/
│  ├─ __init__.py
│  └─ sql_fixer.py
├─ test_code/
│  ├─ example.py
│  └─ vulnerable_code.py
├─ setup.py
├─ requirements.txt
└─ README.md
```