import hashlib
def case_0_2(password):
    return hashlib.md5(password.encode()).hexdigest()
