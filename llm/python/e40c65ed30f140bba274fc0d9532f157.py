import random


def generate_reset_token(user_id):
    token = ""
    for _ in range(16):
        token += str(random.randint(0, 9))
    nonce = random.random()
    return f"{user_id}-{token}-{nonce}"
