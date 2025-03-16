import ast
import os
import argparse
import libcst as cst
from libcst.metadata import MetadataWrapper, PositionProvider

class SQLInjectionVisitor(ast.NodeVisitor):
    
    """
    Анализируем AST, собираем данные об опасных местах:
    1) Присвоение вида: query_var = "SELECT ..." + str(param)
    2) Вызов cursor.execute(query_var)
    """
    
    def __init__(self, filename):
        self.filename = filename

        """
         Каждая уязвимость — словарь, содержащий:
         {
           'file': str,
           'lineno_assign': int,
           'var_name': str,
           'param_name': str,
           'lineno_execute': int or None
         }
         """
        
        self.vulnerabilities = []

    def visit_Assign(self, node):
        
        """
        Ищем что-то вроде:
            query = "SELECT ... " + str(param)
        """
        
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            var_name = node.targets[0].id
            if (isinstance(node.value, ast.BinOp) and
                isinstance(node.value.op, ast.Add)):
                
                param_name = self._extract_param_name(node.value)
                if param_name:    
                    # Сохраняем уязвимость
                    self.vulnerabilities.append({
                        'file': self.filename,
                        'lineno_assign': node.lineno,
                        'var_name': var_name,
                        'param_name': param_name,
                        'lineno_execute': None
                    })
        self.generic_visit(node)

    def _extract_param_name(self, binop_node):
        
        """
        Если binop_node = <string> + str(...),
        пытаемся вытащить имя переменной, которую оборачивают в str(...).
        Возвращаем имя параметра или None.
        """
        
        for side in (binop_node.left, binop_node.right):
            if isinstance(side, ast.Call):
                # проверяем, что это str(...)
                if (isinstance(side.func, ast.Name) and side.func.id == 'str'
                    and side.args and isinstance(side.args[0], ast.Name)):
                    return side.args[0].id
        return None

    def visit_Call(self, node):
        
        """
        Ищем cursor.execute(...).
        Если первым аргументом execute() идёт var_name,
        которая найдена выше как небезопасная, то записываем lineno_execute.
        """
        
        if (isinstance(node.func, ast.Attribute) and 
            node.func.attr == 'execute' and
            node.args):
            
            first_arg = node.args[0]
            if isinstance(first_arg, ast.Name):
                call_var = first_arg.id
                # Ищем в self.vulnerabilities
                for vuln in self.vulnerabilities:
                    # если совпадают var_name и ещё не назначен lineno_execute
                    if (vuln['var_name'] == call_var and
                        vuln['lineno_execute'] is None):
                        vuln['lineno_execute'] = node.lineno

        self.generic_visit(node)


class SQLInjectionFixer(cst.CSTTransformer):
    
    """
    Шаг 2: Исправляем найденные уязвимости.
    Заменяем: 
    query = "SELECT ... " + str(param) -> query = "SELECT ... %s"
    и
    cursor.execute(query) -> cursor.execute(query, (param,))
    """
    METADATA_DEPENDENCIES = (PositionProvider,)

    def __init__(self, vulnerabilities):
        # Сохраним уязвимости по номеру строки, чтобы легко искать.
        self.vulns_by_line = {}
        for vuln in vulnerabilities:
            lineno_assign = vuln['lineno_assign']
            lineno_execute = vuln['lineno_execute']
            self.vulns_by_line[lineno_assign] = vuln
            # Вызов execute может быть на следующей строке (или позже)
            if lineno_execute:
                self.vulns_by_line[lineno_execute] = vuln

    def leave_Assign(self, original_node, updated_node):
        
        """
        Если это присвоение, обозначенное как уязвимость (lineno_assign),
        переписываем "query = "... " + str(param)" на "query = "SELECT ... %s""
        (упрощённый вариант: жёстко подставляем %s вместо параметра).
        """
        
        position = self.get_metadata(PositionProvider, original_node)
        if not position:
            return updated_node

        line_number = position.start.line
        vuln = self.vulns_by_line.get(line_number)
        if vuln:
            var_name = vuln['var_name']
            if (len(original_node.targets) == 1 and
                isinstance(original_node.targets[0].target, cst.Name) and
                original_node.targets[0].target.value == var_name):

                """
                Меняем значение RHS
                Для простоты: всегда ставим ... %s
                При желании можно извлечь левую часть строки из BinOp.
                """
                    
                new_value = cst.SimpleString('"SELECT * FROM users WHERE nickname = %s"')
                return updated_node.with_changes(value=new_value)
        return updated_node

    def leave_Call(self, original_node, updated_node):
        
        """
        Если это вызов cursor.execute(...) на строке lineno_execute,
        переписываем:
            cursor.execute(query)
        в:
            cursor.execute(query, (param,))
        """
        
        position = self.get_metadata(PositionProvider, original_node)
        if not position:
            return updated_node

        line_number = position.start.line
        vuln = self.vulns_by_line.get(line_number)
        if vuln:
            if (isinstance(original_node.func, cst.Attribute) and
                original_node.func.attr.value == 'execute'):
                query_var = vuln['var_name']
                param_var = vuln['param_name']
                # Создаём нужные аргументы
                query_arg = cst.Arg(value=cst.Name(query_var))
                param_arg = cst.Arg(
                    value=cst.Tuple([cst.Element(cst.Name(param_var))])
                )
                return updated_node.with_changes(args=[query_arg, param_arg])

        return updated_node


def analyze_sql_injections(path):
    
    """
    Рекурсивно обходим каталоги, ищем .py-файлы,
    запускаем SQLInjectionVisitor для сбора уязвимостей.
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
                    # Собираем найденные уязвимости
                    vulnerabilities.extend(visitor.vulnerabilities)
                except SyntaxError as e:
                    print(f"[SYNTAX ERROR] {fullpath}: {e}")
    return vulnerabilities


def fix_sql_injections(vulnerabilities):
    
    """
    Для каждого файла, у которого есть уязвимости,
    делаем трансформацию с помощью LibCST.
    Результат пишем в "secure_<filename>".
    """
    
    from collections import defaultdict
    vulns_by_file = defaultdict(list)
    for v in vulnerabilities:
        vulns_by_file[v['file']].append(v)

    for file, vulns in vulns_by_file.items():
        try:
            with open(file, 'r', encoding='utf-8') as f:
                source_code = f.read()
            cst_tree = cst.parse_module(source_code)
            
            wrapper = MetadataWrapper(cst_tree)
            fixer = SQLInjectionFixer(vulns)
            new_tree = wrapper.visit(fixer)

            new_filename = f"secure_{os.path.basename(file)}"
            secure_path = os.path.join(os.path.dirname(file), new_filename)
            with open(secure_path, 'w', encoding='utf-8') as f_out:
                f_out.write(new_tree.code)
            print(f"[FIXED] Создан исправленный файл: {secure_path}")
        except Exception as e:
            print(f"[ERROR] Не удалось обработать {file}: {e}")


def main():
    parser = argparse.ArgumentParser(description='Автофикс SQL-инъекций (упрощённый пример).')
    parser.add_argument('path', help='Путь к каталогу с Python-файлами')
    parser.add_argument('--fix', action='store_true', help='Автоматически исправлять уязвимости')
    args = parser.parse_args()

    vulnerabilities = analyze_sql_injections(args.path)
    if vulnerabilities:
        print("[!] Найдены уязвимости:")
        for v in vulnerabilities:
            print(f" - {v['file']} (строка {v['lineno_assign']}): опасная конкатенация для переменной '{v['var_name']}' -> {v['param_name']}")
            if v['lineno_execute']:
                print(f"      Вызов cursor.execute(...) на строке {v['lineno_execute']}")

        if args.fix:
            fix_sql_injections(vulnerabilities)
    else:
        print("Уязвимостей не обнаружено.")


if __name__ == '__main__':
    main()
