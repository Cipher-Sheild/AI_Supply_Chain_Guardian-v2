def case_3_0(db, value):
    return db.execute(f"SELECT * FROM users WHERE id = {value}")
