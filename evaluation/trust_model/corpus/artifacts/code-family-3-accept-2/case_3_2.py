import sqlite3
def case_3_2(db, value):
    return db.execute("SELECT name FROM users WHERE id = ?", (value,)).fetchall()
