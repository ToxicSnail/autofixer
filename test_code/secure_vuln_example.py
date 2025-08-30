import sqlite3

def vulnerable_query(user_id):
    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()
    
    query = "SELECT * FROM users WHERE id =  %s"  # Уязвимый SQL-запрос (конкатенация строк)
    cursor.execute(query, (user_id,))
    
    query_f = "SELECT * FROM users WHERE id =  %s"  # Еще один уязвимый вариант (f-строка)
    cursor.execute(query_f, (user_id,))
    
    return cursor.fetchall()
