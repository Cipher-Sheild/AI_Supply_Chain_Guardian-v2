import hashlib
def case_0_4(password):
    return hashlib.md5(password.encode()).hexdigest()
