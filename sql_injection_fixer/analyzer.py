# analyzer.py

import ast
import os

def find_sql_injections(path):
    vulnerabilities = []
    for filename in get_python_files(path):
        with open(filename, 'r') as file:
            source_code = file.read()
            tree = ast.parse(source_code, filename=filename)
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
        self.assignments = {}

    def visit_Assign(self, node):
        if isinstance(node.targets[0], ast.Name):
            var_name = node.targets[0].id
            if isinstance(node.value, ast.BinOp) and isinstance(node.value.op, ast.Add):
                print(f"Detected concatenation in assignment to {var_name} at line {node.lineno}")
                self.assignments[var_name] = True
        self.generic_visit(node)

    def visit_Call(self, node):
        if isinstance(node.func, ast.Attribute) and node.func.attr == 'execute':
            print(f"Found execute call at line {node.lineno}")
            print(f"Node details: {ast.dump(node, indent=4)}")
            if self.is_vulnerable(node):
                self.vulnerabilities.append({
                    'file': self.filename,
                    'lineno': node.lineno,
                    'col_offset': node.col_offset,
                    'node': node
                })
        self.generic_visit(node)

    def is_vulnerable(self, node):
        if node.args:
            arg = node.args[0]
            if isinstance(arg, ast.Name):
                if arg.id in self.assignments:
                    print(f"Variable {arg.id} passed to execute at line {node.lineno} is vulnerable")
                    return True
            elif isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                print(f"Detected concatenation at line {node.lineno}")
                print(f"Node details: {ast.dump(arg, indent=4)}")
                return True
            elif isinstance(arg, ast.FormattedValue):
                return True
        return False
