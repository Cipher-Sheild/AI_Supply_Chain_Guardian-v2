def case_3_1(db, value):
    return db.execute(f"SELECT * FROM users WHERE id = {value}")
