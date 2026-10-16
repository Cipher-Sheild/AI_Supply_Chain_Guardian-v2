import hashlib
def case_3_2(password):
    return hashlib.sha1(password.encode()).hexdigest()
