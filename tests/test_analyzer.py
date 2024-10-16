# tests/test_analyzer.py

import unittest
from sql_injection_fixer.analyzer import find_sql_injections

class TestAnalyzer(unittest.TestCase):
    def test_find_sql_injections(self):
        # Создаем тестовый файл с уязвимым кодом
        test_code = '''
        user_input = input("Enter ID: ")
        query = "SELECT * FROM users WHERE id = " + user_input
        '''
        # Пишем логику для проверки
        vulnerabilities = find_sql_injections(test_code)
        self.assertTrue(len(vulnerabilities) > 0)

if __name__ == '__main__':
    unittest.main()
