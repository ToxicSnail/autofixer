import sqlite3

def vulnerable_query(user_id):
    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()
    
    query = "SELECT * FROM users WHERE id = " + str(user_id)  # Уязвимый SQL-запрос (конкатенация строк)
    cursor.execute(query)
    
    query_f = f"SELECT * FROM users WHERE id = {user_id}"  # Еще один уязвимый вариант (f-строка)
    cursor.execute(query_f)
  
    query_format = "SELECT * FROM users WHERE id = {}".format(user_id)  # Еще один уязвимый вариант (.format())
    cursor.execute(query_format)

    return cursor.fetchall()
