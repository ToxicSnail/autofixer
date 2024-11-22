# sql_injection_fixer/utils.py

def sanitize_input(input_string):
    # Пример экранирования входных данных
    return input_string.replace("'", "''")
