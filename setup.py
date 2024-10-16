# setup.py

from setuptools import setup, find_packages

setup(
    name='sql_injection_fixer',
    version='0.1',
    packages=find_packages(),
    install_requires=[
        # Зависимости
    ],
    entry_points={
        'console_scripts': [
            'sql-fix=sql_injection_fixer.main:main',
        ],
    },
)
