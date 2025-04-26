# challenge/four_challenges.py

import random

# Challenge Types:
# 00: Standard Fiat-Shamir
# 01: Horizontal hyperbola
# 10: Vertical hyperbola
# 11: Modified Fiat-Shamir (r * s mod n)

def generate_challenge(message: bytes, commitment: dict) -> str:
    """Generates one of four challenge types deterministically."""
    # For demo: Use random. In real world, use hash(message || commitment)
    challenge = random.choice(['00', '01', '10', '11'])
    return challenge

def respond_to_challenge(challenge: str, secret_data: dict, private_key: dict, public_key: dict) -> dict:
    x = secret_data['x']
    y = secret_data['y']
    h = secret_data['h']
    k = secret_data['k']
    a = secret_data['a']
    b = secret_data['b']
    n = private_key['n']
    r = secret_data['r']
    s = private_key['s']

    if challenge == '00':
        # Fiat-Shamir: Reveal y, check y^2 ≡ x mod n
        return {'y': y}

    elif challenge == '01':
        # Horizontal Hyperbola: Reveal x, verifier will check (x−h)^2/a^2 − (y−k)^2/b^2 = 1
        return {'x': x, 'h': h, 'k': k, 'a': a, 'b': b}

    elif challenge == '10':
        # Vertical Hyperbola: Reveal y, verifier checks (y−k)^2/b^2 − (x−h)^2/a^2 = 1
        return {'y': y, 'h': h, 'k': k, 'a': a, 'b': b}

    elif challenge == '11':
        # Modified FS: y = r * s mod n; verifier checks y^2 ≡ x * v mod n
        y_new = (r * s) % n
        return {'y': y_new}

    else:
        raise ValueError("Invalid challenge type")
