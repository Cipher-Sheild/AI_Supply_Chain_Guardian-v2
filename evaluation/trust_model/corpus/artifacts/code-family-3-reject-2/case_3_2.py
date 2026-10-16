def case_3_2(db, value):
    return db.execute(f"SELECT * FROM users WHERE id = {value}")
