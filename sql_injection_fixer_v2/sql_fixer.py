import ast
import os
import argparse
import libcst as cst
from libcst.metadata import MetadataWrapper, PositionProvider

class SQLInjectionVisitor(ast.NodeVisitor):
    def __init__(self, filename):
        self.filename = filename
        self.vulnerabilities = []      # список уязвимостей
        self.unsafe_vars = {}          # { var_name: (True, param_name) }

    def visit_Assign(self, node):
        # Проверяем, что это присвоение вида "var_name = <что-то>"
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            var_name = node.targets[0].id
            # Если это конкатенация c BinOp
            if isinstance(node.value, ast.BinOp) and isinstance(node.value.op, ast.Add):
                # И проверяем, не похоже ли правое слагаемое на str(...)?
                param_name = self.extract_param_from_str(node.value)
                if param_name:
                    # Помечаем переменную var_name как небезопасную + храним имя параметра
                    self.unsafe_vars[var_name] = (True, param_name)
        self.generic_visit(node)

    def extract_param_from_str(self, binop_node):
        """
        Если binop_node выглядит как: "SOMETHING + str(<param>)",
        вернём имя <param>. Иначе None
        """
        # binop_node.left, binop_node.right
        # Ищем в любом из слагаемых вызов str(х)
        for side in (binop_node.left, binop_node.right):
            if isinstance(side, ast.Call):
                if isinstance(side.func, ast.Name) and side.func.id == 'str':
                    if side.args and isinstance(side.args[0], ast.Name):
                        return side.args[0].id
        return None

    def visit_Call(self, node):
        # Ищем cursor.execute(...)
        if (isinstance(node.func, ast.Attribute) and 
            node.func.attr == 'execute'):
            if node.args:
                first_arg = node.args[0]
                # Если первый аргумент - имя переменной (например string)
                if isinstance(first_arg, ast.Name):
                    var_name = first_arg.id
                    if var_name in self.unsafe_vars:
                        unsafe_info = self.unsafe_vars[var_name]  # (True, param_name)
                        if unsafe_info[0] is True:
                            param_name = unsafe_info[1]
                            self.vulnerabilities.append({
                                'file': self.filename,
                                'lineno': node.lineno,
                                'desc': f'Вызов execute() с небезопасной переменной "{var_name}"',
                                'query_var': var_name,     # сохраняем имя переменной с запросом
                                'param_var': param_name    # сохраняем имя вклеиваемого параметра
                            })
        self.generic_visit(node)



class SQLInjectionFixer(cst.CSTTransformer):
    METADATA_DEPENDENCIES = (PositionProvider,)

    def __init__(self, vulnerabilities):
        self.vulnerabilities = vulnerabilities

    def leave_Call(self, original_node, updated_node):
        if (isinstance(original_node.func, cst.Attribute) and
            original_node.func.attr.value == 'execute'):
            
            position = self.get_metadata(PositionProvider, original_node)
            if not position:
                return updated_node

            line_number = position.start.line

            for vuln in self.vulnerabilities:
                if vuln['lineno'] == line_number:
                    # Получаем имена, сохранённые в Visitor
                    query_var = vuln.get('query_var', 'query')
                    param_var = vuln.get('param_var', 'user_id')

                    # "string" идёт первым аргументом,
                    safe_sql = cst.Name(query_var)
                    # "(nickname,)" идёт вторым аргументом
                    safe_param = cst.Tuple(elements=[
                        cst.Element(value=cst.Name(param_var))
                    ])

                    return updated_node.with_changes(
                        args=[
                            cst.Arg(value=safe_sql),
                            cst.Arg(value=safe_param)
                        ]
                    )

        return updated_node



def analyze_sql_injections(path):
    """
    Рекурсивно проходимся по файлам, собираем все уязвимости.
    """
    vulnerabilities = []
    for root, _, files in os.walk(path):
        for filename in files:
            if filename.endswith('.py'):
                fullpath = os.path.join(root, filename)
                with open(fullpath, 'r', encoding='utf-8') as f:
                    code = f.read()
                try:
                    tree = ast.parse(code, filename=fullpath)
                    visitor = SQLInjectionVisitor(fullpath)
                    visitor.visit(tree)
                    vulnerabilities.extend(visitor.vulnerabilities)
                except SyntaxError as e:
                    print(f"Ошибка синтаксиса в файле {fullpath}: {e}")
    return vulnerabilities

def fix_sql_injections(vulnerabilities):
    """
    Сгруппируем уязвимости по файлам, и для каждого файла выполним трансформацию libCST.
    """
    from collections import defaultdict
    vulns_by_file = defaultdict(list)
    for v in vulnerabilities:
        vulns_by_file[v['file']].append(v)

    for file, vulns in vulns_by_file.items():
        with open(file, 'r', encoding='utf-8') as f:
            source_code = f.read()
        cst_tree = cst.parse_module(source_code)
        
        wrapper = MetadataWrapper(cst_tree)
        fixer = SQLInjectionFixer(vulns)
        new_tree = wrapper.visit(fixer)

        new_filename = f"secure_{os.path.basename(file)}"
        with open(new_filename, 'w', encoding='utf-8') as f_out:
            f_out.write(new_tree.code)
        print(f"[FIX] Создан исправленный файл: {new_filename}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('path', help='Путь к каталогу с Python-файлами')
    parser.add_argument('--fix', action='store_true', help='Автоматически исправлять уязвимости')
    args = parser.parse_args()

    vulnerabilities = analyze_sql_injections(args.path)
    if vulnerabilities:
        print("\nНайдены уязвимости:")
        for v in vulnerabilities:
            print(f" - {v['file']} (строка {v['lineno']}): {v['desc']}")
        if args.fix:
            fix_sql_injections(vulnerabilities)
    else:
        print("✅ Уязвимостей не найдено.")

if __name__ == "__main__":
    main()
