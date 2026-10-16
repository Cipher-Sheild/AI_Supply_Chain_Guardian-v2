import requests
def case_1_2():
    return requests.get("https://example.org/item/2", verify=False)
