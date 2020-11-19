import random
import string
def is_valid_payload(payload, policy):
    for item in policy:
        if not item in payload:
            return False
    return True
def get_random_string(length):
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str
get_bin = lambda x: format(x, 'b')
