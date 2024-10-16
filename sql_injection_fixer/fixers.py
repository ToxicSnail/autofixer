# sql_injection_fixer/fixers.py

import ast
import astor

def fix_sql_injections(vulnerabilities):
    files_to_fix = set(vuln['file'] for vuln in vulnerabilities)
    for filename in files_to_fix:
        fix_vulnerabilities_in_file(filename, vulnerabilities)

def fix_vulnerabilities_in_file(filename, vulnerabilities):
    with open(filename, 'r') as file:
        source_code = file.read()
        tree = ast.parse(source_code, filename=filename)

    fixer = SQLInjectionFixer(vulnerabilities)
    fixer.visit(tree)

    fixed_code = astor.to_source(tree)
    with open(filename, 'w') as file:
        file.write(fixed_code)

class SQLInjectionFixer(ast.NodeTransformer):
    def __init__(self, vulnerabilities):
        self.vulnerabilities = vulnerabilities

    def visit_Call(self, node):
        for vuln in self.vulnerabilities:
            if node.lineno == vuln['lineno']:
                return self.fix_node(node)
        return self.generic_visit(node)

    def fix_node(self, node):
        # Заменяем конкатенацию на параметризованный запрос
        query_arg = node.args[0]
        if isinstance(query_arg, ast.BinOp):
            params = self.extract_params(query_arg)
            new_query = ast.Str(s="SELECT * FROM users WHERE id = ?")
            new_args = [new_query, ast.List(elts=params, ctx=ast.Load())]
            node.args = new_args
        return node

    def extract_params(self, node):
        # Рекурсивно извлекаем параметры из узла конкатенации
        params = []
        if isinstance(node, ast.BinOp):
            params.extend(self.extract_params(node.left))
            params.extend(self.extract_params(node.right))
        elif isinstance(node, ast.Name):
            params.append(node)
        elif isinstance(node, ast.Call):
            params.append(node)
        return params
