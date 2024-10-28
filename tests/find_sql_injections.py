import pytest
from analyzer import find_sql_injections

# Тест для функции find_sql_injections - проверяет обнаружение SQL-инъекций в коде с конкатенацией строк
def test_find_sql_injections_with_vulnerabilities(tmp_path):
    code = '''import sqlite3
conn = sqlite3.connect(':memory:')
cur = conn.cursor()
user_id = "1 OR 1=1"
cur.execute("SELECT * FROM users WHERE id = " + user_id)
'''
    test_file = tmp_path / "vulnerable_code.py"
    test_file.write_text(code)
    
    vulnerabilities = find_sql_injections(str(tmp_path))
    assert len(vulnerabilities) == 1
    assert vulnerabilities[0]['file'] == str(test_file)
    assert vulnerabilities[0]['lineno'] == 5

# Тест для функции find_sql_injections - проверяет отсутствие SQL-инъекций в безопасном коде
def test_find_sql_injections_without_vulnerabilities(tmp_path):
    code = '''import sqlite3
conn = sqlite3.connect(':memory:')
cur = conn.cursor()
cur.execute("SELECT * FROM users WHERE id = ?", (1,))
'''
    test_file = tmp_path / "safe_code.py"
    test_file.write_text(code)
    
    vulnerabilities = find_sql_injections(str(tmp_path))
    assert len(vulnerabilities) == 0
