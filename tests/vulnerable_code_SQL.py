# vulnerable_code.py

import sqlite3

def get_user_data(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    result = cursor.fetchall()
    conn.close()
    return result

user_input = input("Введите ваш ID пользователя: ")
data = get_user_data(user_input)
print(data)
