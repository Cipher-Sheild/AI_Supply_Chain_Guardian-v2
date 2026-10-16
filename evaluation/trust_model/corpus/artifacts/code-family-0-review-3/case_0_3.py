import hashlib
def case_0_3(password):
    return hashlib.md5(password.encode()).hexdigest()
