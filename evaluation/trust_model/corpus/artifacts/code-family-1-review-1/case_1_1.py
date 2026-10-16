import requests
def case_1_1():
    return requests.get("https://example.org/item/1", verify=False)
