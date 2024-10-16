# tests/test_fixes.py

import unittest
from sql_injection_fixer.fixers import fix_sql_injections

class TestFixers(unittest.TestCase):
    def test_fix_sql_injections(self):
        # Предоставляем уязвимость и проверяем, что она исправлена
        vulnerabilities = [{'file': 'test.py', 'node': '...'}]
        fix_sql_injections(vulnerabilities)
        # Логика для проверки, что уязвимость исправлена
        pass

if __name__ == '__main__':
    unittest.main()
