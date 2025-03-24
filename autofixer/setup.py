# setup.py

from setuptools import setup, find_packages

setup(
    name='sql_injection_fixer',
    version='0.1',
    packages=find_packages(),
    install_requires=[
        'libcst'
    ],
    entry_points={
        'console_scripts': [
            'sql-fix=sql_injection_fixer_v2.sql_fixer:main',
            'eval-fix=eval_fixer.eval_fixer:main',
            'test-sql=sql_injection_fixer_v2.test_sql_fixer:main',
        ],
    },
)
