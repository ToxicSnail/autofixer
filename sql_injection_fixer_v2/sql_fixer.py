import ast
import libcst as cst
import os
import json
import argparse
from libcst.metadata import PositionProvider
from libcst.metadata import MetadataWrapper, PositionProvider

class SQLInjectionVisitor(ast.NodeVisitor):
    def __init__(self, filename):
        self.filename = filename
        self.vulnerabilities = []
        self.assignments = {}

    def visit_Assign(self, node):
        if isinstance(node.targets[0], ast.Name):
            var_name = node.targets[0].id
            if isinstance(node.value, ast.BinOp) and isinstance(node.value.op, ast.Add):
                self.assignments[var_name] = True
        self.generic_visit(node)

    def visit_Call(self, node):
        if isinstance(node.func, ast.Attribute) and node.func.attr == 'execute':
            if self.is_vulnerable(node):
                self.vulnerabilities.append({
                    'file': self.filename,
                    'lineno': node.lineno,
                    'col_offset': node.col_offset,
                    'node': ast.dump(node)
                })
        self.generic_visit(node)

    def is_vulnerable(self, node):
        if not node.args:
            return False

        arg = node.args[0]
        
        def contains_vulnerability(sub_node):
            if isinstance(sub_node, ast.BinOp) and isinstance(sub_node.op, ast.Add):
                return True
            if isinstance(sub_node, ast.JoinedStr):
                return True
            if isinstance(sub_node, ast.Call) and isinstance(sub_node.func, ast.Attribute) and sub_node.func.attr == 'format':
                return True
            if isinstance(sub_node, ast.Name) and sub_node.id in self.assignments:
                return True
            for child in ast.iter_child_nodes(sub_node):
                if contains_vulnerability(child):
                    return True
            return False

        return contains_vulnerability(arg)


class SQLInjectionFixer(cst.CSTTransformer):
    METADATA_DEPENDENCIES = (PositionProvider,)

    def __init__(self, vulnerabilities):
        self.vulnerabilities = vulnerabilities

    def leave_Call(self, original_node, updated_node):
        if isinstance(original_node.func, cst.Attribute) and original_node.func.attr.value == 'execute':
            position = self.get_metadata(PositionProvider, original_node)
            if position:
                line_number = position.start.line
                for vuln in self.vulnerabilities:
                    if vuln['lineno'] == line_number:
                        return updated_node.with_changes(
                            args=[cst.Arg(value=cst.SimpleString("'SELECT * FROM users WHERE id = ?'")),
                                  cst.Arg(value=cst.List([]))]
                        )
        return updated_node



def analyze_sql_injections(path):
    vulnerabilities = []
    for root, _, files in os.walk(path):
        for file in files:
            if file.endswith('.py'):
                filename = os.path.join(root, file)
                with open(filename, 'r') as f:
                    source_code = f.read()
                    tree = ast.parse(source_code, filename=filename)
                    visitor = SQLInjectionVisitor(filename)
                    visitor.visit(tree)
                    vulnerabilities.extend(visitor.vulnerabilities)
    return vulnerabilities


def fix_sql_injections(vulnerabilities):
    for vuln in vulnerabilities:
        filename = vuln['file']
        with open(filename, 'r') as f:
            source_code = f.read()
            tree = cst.parse_module(source_code)
            fixer = SQLInjectionFixer(vulnerabilities)
            
            wrapper = MetadataWrapper(tree)
            fixer = SQLInjectionFixer(vulnerabilities)
            wrapper.resolve(PositionProvider)  # Генерируем метаданные
            modified_tree = wrapper.visit(fixer)

            new_filename = f"secure_{os.path.basename(filename)}"
            with open(new_filename, 'w') as f_out:
                f_out.write(modified_tree.code)
            print(f"✔️ Fixed file created: {new_filename}")


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
        fix_sql_injections(vulnerabilities)
    else:
        print("✅ No vulnerabilities found.")

if __name__ == "__main__":
    main()
