import hashlib
def case_0_1(password):
    return hashlib.md5(password.encode()).hexdigest()
