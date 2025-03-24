import argparse
import sys

GREEN = "\033[92m"
BLUE = "\033[94m"
YELLOW = "\033[93m"
RESET = "\033[0m"

# from sql_injection_fixer_v2.sql_fixer import analyze_sql_injections, fix_sql_injections
from sql_injection_fixer_v2.test_sql_fixer import analyze_sql_injections, fix_sql_injections
from eval_fixer.eval_fixer import analyze_eval_calls, fix_eval_calls

def print_banner():
    """
    Выводит ASCII-баннер (пример).
    """
    banner = r"""
        _    _    _     ___   __     _    _
   /_\ | |  | | _| |_  / _ \ / _|(_)\ \  / /__  _ __
  / _ \| |  | ||_   _|| | | | |_ | | \ \/ / _ \| '__|
 / ___ \ \_/  |  | |_ | |_| |  _|| | / /\ \  _/| |
/_/   \_\__/|_|   \__\ \___/|_|  |_|/_/  \_\__||_|
    """
    print(f"{GREEN}{banner}{RESET}")
    print(f"{YELLOW}AutoFixer: исправление SQL-инъекций и eval-вызовов в Python-коде{RESET}\n")


def run_sql_injection_fixer(path, fix):
    vulnerabilities = analyze_sql_injections(path)
    if vulnerabilities:
        print(f"{BLUE}[!] Найдены уязвимости SQL-инъекций:{RESET}")
        for v in vulnerabilities:
            print(f" - {v['file']} (строка {v['lineno_assign']}): опасная конкатенация для переменной '{v['var_name']}' -> {v['param_name']}")
            if v['lineno_execute']:
                print(f"      Вызов cursor.execute(...) на строке {v['lineno_execute']}")
        if fix:
            fix_sql_injections(vulnerabilities)
    else:
        print("Уязвимостей SQL-инъекций не обнаружено.")

def run_eval_fixer(path, fix):
    eval_calls = analyze_eval_calls(path)
    if eval_calls:
        print(f"{BLUE}[!] Найдены вызовы eval():{RESET}")
        for call in eval_calls:
            print(f" - {call['file']} (строка {call['lineno']}): eval({call['args']})")
        if fix:
            fix_eval_calls(eval_calls)
    else:
        print("Вызовов eval() не обнаружено.")

def main():
    print_banner()

    if len(sys.argv) == 1:
        print("Вы не передали аргументы. Переходим в интерактивный режим.\n")

        while True:
            tool = input("Выберите инструмент (sql, eval, all): ").strip().lower()
            if tool in ["sql", "eval", "all"]:
                break
            else:
                print("Неверный выбор инструмента. Повторите ввод.\n")

        while True:
            path = input("Введите путь к каталогу или файлу: ").strip()
            if path:
                if not os.path.exists(path):
                    print(f"Указанный путь '{path}' не существует. Повторите ввод.\n")
                else:
                    break
            else:
                print("Путь не может быть пустым. Повторите ввод.\n")

        while True:
            fix_answer = input("Использовать автоматическое исправление (y/n)? ").strip().lower()
            if fix_answer in ["y", "yes", "n", "no"]:
                fix = fix_answer in ("y", "yes")
                break
            else:
                print("Неверный ввод. Введите 'y' или 'n'.\n")

    else:
        parser = argparse.ArgumentParser(
            description="Запуск автофикса SQL-инъекций и eval-вызовов."
        )
        parser.add_argument(
            "tool",
            choices=["sql", "eval", "all"],
            help="Какой инструмент запустить: sql, eval или all (оба).",
        )
        parser.add_argument(
            "path",
            help="Путь к каталогу или файлу, который нужно просканировать."
        )
        parser.add_argument(
            "--fix",
            action="store_true",
            help="Автоматически исправлять уязвимости, если они найдены."
        )
        args = parser.parse_args()

        tool = args.tool
        path = args.path
        fix = args.fix

    if tool == "sql":
        run_sql_injection_fixer(path, fix)
    elif tool == "eval":
        run_eval_fixer(path, fix)
    elif tool == "all":
        print(f"{GREEN}--= Запуск SQL Injection Fixer =--{RESET}")
        run_sql_injection_fixer(path, fix)
        print("\n" + "-" * 50 + "\n")
        print(f"{GREEN}--= Запуск eval() Fixer =--{RESET}")
        run_eval_fixer(path, fix)

if __name__ == "__main__":
    main()