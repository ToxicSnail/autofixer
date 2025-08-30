import sqlite3

def vulnerable_query(user_id):
    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()

    # Уязвимый SQL-запрос (конкатенация строк)
    pole_1 = "SELECT * FROM users WHERE nickname =  %s"
    cursor.execute(pole_1, (string,))

    # Еще один уязвимый вариант (f-строка)
    query_f = "SELECT * FROM users WHERE id =  %s"
    cursor.execute(query_f, (user_id,))

    # Еще один уязвимый вариант (.format())
    query_format = "SELECT * FROM users WHERE id = {}".format(user_id)
    cursor.execute(query_format)

    return cursor.fetchall()
