# sql_injection_fixer/analyzer.py

import ast
import os

def find_sql_injections(path):
    vulnerabilities = []
    for filename in get_python_files(path):
        with open(filename, 'r') as file:
            tree = ast.parse(file.read(), filename=filename)
            visitor = SQLInjectionVisitor(filename)
            visitor.visit(tree)
            vulnerabilities.extend(visitor.vulnerabilities)
    return vulnerabilities

def get_python_files(path):
    python_files = []
    for root, dirs, files in os.walk(path):
        for file in files:
            if file.endswith('.py'):
                python_files.append(os.path.join(root, file))
    return python_files

class SQLInjectionVisitor(ast.NodeVisitor):
    def __init__(self, filename):
        self.filename = filename
        self.vulnerabilities = []

    def visit_Call(self, node):
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == 'execute':
                if self.is_vulnerable(node):
                    self.vulnerabilities.append({
                        'file': self.filename,
                        'lineno': node.lineno,
                        'col_offset': node.col_offset,
                        'node': node
                    })
        self.generic_visit(node)

    def is_vulnerable(self, node):
        # Проверяем, есть ли конкатенация в аргументах execute()
        if node.args:
            arg = node.args[0]
            if isinstance(arg, ast.BinOp):
                return True
        return False
