import ast
import os
import argparse
import libcst as cst
from libcst.metadata import MetadataWrapper, PositionProvider

class EvalVisitor(ast.NodeVisitor):

    """
    Анализируем AST для поиска вызовов eval(...)
    """
    
    def __init__(self, filename):
        self.filename = filename
        self.eval_calls = []

    def visit_Call(self, node):
        if isinstance(node.func, ast.Name) and node.func.id == 'eval':
            self.eval_calls.append( # Добавляем вызовы eval в список
                {
                'file': self.filename,
                'lineno': node.lineno,
                'args': node.args  # Сохраняем аргументы eval
            })
        self.generic_visit(node)


class EvalFixer(cst.CSTTransformer):

    """
    Заменяет вызовы eval(...) на ast.literal_eval(...)
    """

    METADATA_DEPENDENCIES = (PositionProvider,)

    def __init__(self, eval_calls):
        self.eval_calls_map = {call['lineno']: call for call in eval_calls} # Сохраняем все вызовы eval, чтобы затем изменить их

    def leave_Call(self, original_node, updated_node):

        """
        Заменяем вызов eval() на ast.literal_eval()
        """

        position = self.get_metadata(PositionProvider, original_node)
        if not position:
            return updated_node

        line_number = position.start.line
        if line_number in self.eval_calls_map:
            if isinstance(original_node.func, cst.Name) and original_node.func.value == 'eval': # Заменяем eval на ast.literal_eval
                new_func = cst.Attribute(    # Меняем имя функции на ast.literal_eval
                    value=cst.Name("ast"),
                    attr=cst.Name("literal_eval")
                )
                return updated_node.with_changes(func=new_func) # Возвращаем обновленный вызов

        return updated_node


class InsertImportTransformer(cst.CSTTransformer):

    """
    Добавляет импорт ast, если его нет в коде.
    """
    
    def __init__(self, module_name: str):
        self.module_name = module_name
        self.import_inserted = False

    def leave_Module(self, original_node, updated_node):
        if not self.import_inserted:
            
            import_node = cst.SimpleStatementLine( # Добавляем импорт в начало файла
                body=[cst.Import(names=[cst.ImportAlias(name=cst.Name(self.module_name))])]
            )
            new_body = [import_node] + list(updated_node.body)
            self.import_inserted = True
            return updated_node.with_changes(body=new_body)
        return updated_node


def analyze_eval_calls(path):

    """
    Рекурсивно обходим каталог, ищем все вызовы eval() и собираем информацию.
    """

    eval_calls = []
    for root, _, files in os.walk(path):
        for filename in files:
            if filename.endswith('.py'):
                fullpath = os.path.join(root, filename)
                with open(fullpath, 'r', encoding='utf-8') as f:
                    code = f.read()
                try:
                    tree = ast.parse(code, filename=fullpath)
                    visitor = EvalVisitor(fullpath)
                    visitor.visit(tree)
                    eval_calls.extend(visitor.eval_calls) # Собираем вызовы eval
                except SyntaxError as e:
                    print(f"[SYNTAX ERROR] {fullpath}: {e}")
    return eval_calls


def fix_eval_calls(eval_calls):

    """
    Исправляем все вызовы eval() на ast.literal_eval()
    """

    from collections import defaultdict
    eval_calls_by_file = defaultdict(list)
    for call in eval_calls:
        eval_calls_by_file[call['file']].append(call)

    for file, calls in eval_calls_by_file.items():
        try:
            with open(file, 'r', encoding='utf-8') as f:
                source_code = f.read()
            cst_tree = cst.parse_module(source_code)
            
            wrapper = MetadataWrapper(cst_tree) # Применяем фикс для eval() вызовов
            fixer = EvalFixer(calls)
            new_tree = wrapper.visit(fixer)
            
            new_tree = new_tree.visit(InsertImportTransformer("ast"))   # Добавляем импорт ast, если его нет

            new_filename = f"secure_{os.path.basename(file)}"   # Пишем в новый файл
            secure_path = os.path.join(os.path.dirname(file), new_filename)
            with open(secure_path, 'w', encoding='utf-8') as f_out:
                f_out.write(new_tree.code)
            print(f"[FIXED] Corrected file created: {secure_path}")
        except Exception as e:
            print(f"[ERROR] Failed to process {file}: {e}")


def main():
    parser = argparse.ArgumentParser(description='Autofix eval() usage (simplified example).')
    parser.add_argument('path', help='Path to the directory with Python files')
    parser.add_argument('--fix', action='store_true', help='Automatically fix eval vulnerabilities')
    args = parser.parse_args()

    # Шаг 1. Сбор всех вызовов eval
    eval_calls = analyze_eval_calls(args.path)
    if eval_calls:
        print("[!] eval calls found:")
        for call in eval_calls:
            print(f" - {call['file']} (line {call['lineno']}): eval({call['args']})")

        # Шаг 2. При необходимости делаем фиксы
        if args.fix:
            fix_eval_calls(eval_calls)
    else:
        print("No eval calls found.")


if __name__ == '__main__':
    main()
