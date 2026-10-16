import hashlib
def case_3_4(password):
    return hashlib.sha1(password.encode()).hexdigest()
