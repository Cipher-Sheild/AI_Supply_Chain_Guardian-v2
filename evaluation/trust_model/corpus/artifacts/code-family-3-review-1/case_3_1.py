import hashlib
def case_3_1(password):
    return hashlib.sha1(password.encode()).hexdigest()
