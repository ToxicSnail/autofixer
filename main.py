import argparse
import sys

GREEN = "\033[92m"
BLUE = "\033[94m"
YELLOW = "\033[93m"
RESET = "\033[0m"

from sql_injection_fixer_v2.sql_fixer import analyze_sql_injections, fix_sql_injections
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

    if args.tool == "sql":
        run_sql_injection_fixer(args.path, args.fix)

    elif args.tool == "eval":
        run_eval_fixer(args.path, args.fix)

    elif args.tool == "all":
        print(f"{GREEN}--= Запуск SQL Injection Fixer =--{RESET}")
        run_sql_injection_fixer(args.path, args.fix)
        print("\n" + "-" * 50 + "\n")
        print(f"{GREEN}--= Запуск eval() Fixer =--{RESET}")
        run_eval_fixer(args.path, args.fix)

if __name__ == "__main__":
    main()
