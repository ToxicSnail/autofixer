import ast
import libcst as cst
import os
import json
import argparse

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
        print(f"Visiting function call: {ast.dump(node, indent=4)}")
        if isinstance(node.func, ast.Attribute) and node.func.attr == 'execute':
            print(f"Found execute() call at line {node.lineno}")
            if self.is_vulnerable(node):
                self.vulnerabilities.append({
                    'file': self.filename,
                    'lineno': node.lineno,
                    'col_offset': node.col_offset,
                    'node': ast.dump(node)
                })
        self.generic_visit(node)

    def is_vulnerable(self, node):
        if node.args:
            arg = node.args[0]
            print(f"\n Analyzing argument in line {node.lineno}: {ast.dump(arg, indent=4)}")
            
            if isinstance(arg, ast.Name) and arg.id in self.assignments:
                print(f" Found variable {arg.id} being passed to execute() at line {node.lineno}")
                return True
            elif isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                print(f" Found string concatenation in execute() at line {node.lineno}")
                return True
            elif isinstance(arg, ast.JoinedStr):  # Проверка f-строк
                print(f" Found f-string in execute() at line {node.lineno}")
                return True
            elif isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute) and arg.func.attr == 'format':
                print(f" Found .format() usage in execute() at line {node.lineno}")
                return True
        return False

class SQLInjectionFixer(cst.CSTTransformer):
    def __init__(self, vulnerabilities):
        self.vulnerabilities = vulnerabilities

    def leave_Call(self, original_node, updated_node):
        if isinstance(original_node.func, cst.Attribute) and original_node.func.attr.value == 'execute':
            for vuln in self.vulnerabilities:
                if vuln['lineno'] == original_node.lineno:
                    return updated_node.with_changes(
                        args=[cst.Arg(value=cst.SimpleString("'SELECT * FROM users WHERE id = ?'")),
                              cst.Arg(value=cst.List([]))]
                    )
        return updated_node


def analyze_sql_injections(path):
    vulnerabilities = []
    for root, _, files in os.walk(path):
        print(f" Scanning directory: {path}")
        for file in files:
            print(f" Found Python file: {file}")
            if file.endswith('.py'):
                print(f" Processing: {file}")
                filename = os.path.join(root, file)
                print(f"Analyzing file: {filename}")
                print(f" Reading file: {filename}")
        with open(filename, 'r') as f:
                    source_code = f.read()
                    tree = ast.parse(source_code, filename=filename)
                    visitor = SQLInjectionVisitor(filename)
                    visitor.visit(tree)
                    vulnerabilities.extend(visitor.vulnerabilities)
    return vulnerabilities


def fix_sql_injections(vulnerabilities):
    print(" Detected vulnerabilities:")
    for vuln in vulnerabilities:
        filename = vuln['file']
        print(f" Reading file: {filename}")
        with open(filename, 'r') as f:
            source_code = f.read()
            tree = cst.parse_module(source_code)
            fixer = SQLInjectionFixer(vulnerabilities)
            modified_tree = tree.visit(fixer)
            new_filename = f"secure_{os.path.basename(filename)}"
            with open(new_filename, 'w') as f_out:
                f_out.write(modified_tree.code)
            print(f" Fixed file created: {new_filename}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('path', help='Directory containing Python files')
    parser.add_argument('--fix', action='store_true', help='Fix found vulnerabilities')
    parser.add_argument('--json', action='store_true', help='Output report in JSON format')
    args = parser.parse_args()

    vulnerabilities = analyze_sql_injections(args.path)

    if vulnerabilities:
        print("\n⚠️ Found vulnerabilities:")
        for vuln in vulnerabilities:
            print(f"File: {vuln['file']}, Line: {vuln['lineno']}")
        if args.json:
            print(json.dumps(vulnerabilities, indent=4))
        if args.fix:
            fix_sql_injections(vulnerabilities)
    else:
        print(" No vulnerabilities found.")

if __name__ == "__main__":
    main()
