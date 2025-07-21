import random
import math

def generate_commitment(secret_data, public_params):
    """
    Generate commitment values (x, y) and hyperbola parameters.
    secret_data: dict with secret values (e.g., witness, randomness)
    public_params: dict with public parameters (e.g., modulus n)
    Returns: dict with x, y, h, k, a, b, r, s, v (as needed)
    """
    n = public_params['n']
    # Example: generate random secrets and hyperbola params
    s = random.randint(2, n-2)
    r = random.randint(2, n-2)
    h = random.randint(1, n-1)
    k = random.randint(1, n-1)
    a = random.randint(2, n//4)
    b = random.randint(2, n//4)
    # For Fiat-Shamir, x = y^2 mod n
    y = s
    x = pow(y, 2, n)
    # For challenge 11, v is a public value
    v = public_params.get('v', random.randint(2, n-2))
    return {'x': x, 'y': y, 'h': h, 'k': k, 'a': a, 'b': b, 'r': r, 's': s, 'v': v}

def generate_commitment_for_challenge(challenge, public_params):
    """
    Generate a commitment that is only valid for the specified challenge type.
    This ensures strict soundness: only the correct challenge will verify.
    """
    n = public_params['n']
    if challenge == '00':
        y = random.randint(2, n-2)
        x = pow(y, 2, n)
        h = random.randint(1, n-1)
        k = random.randint(1, n-1)
        a = random.randint(2, n//4)
        b = random.randint(2, n//4)
        r = random.randint(2, n-2)
        s = random.randint(2, n-2)
        v = public_params.get('v', random.randint(2, n-2))
        return {'x': x, 'y': y, 'h': h, 'k': k, 'a': a, 'b': b, 'r': r, 's': s, 'v': v}
    elif challenge == '01':
        h = random.randint(1, n-1)
        k = random.randint(1, n-1)
        a = random.randint(2, n//4)
        b = random.randint(2, n//4)
        lower = h + a + 1
        upper = n - 1
        if lower > upper:
            lower = upper
        x = random.randint(lower, upper)
        y_val = math.sqrt((x-h)**2 / a**2 - 1) * b + k
        y = int(round(y_val))
        r = random.randint(2, n-2)
        s = random.randint(2, n-2)
        v = public_params.get('v', random.randint(2, n-2))
        return {'x': x, 'y': y, 'h': h, 'k': k, 'a': a, 'b': b, 'r': r, 's': s, 'v': v}
    elif challenge == '10':
        h = random.randint(1, n-1)
        k = random.randint(1, n-1)
        a = random.randint(2, n//4)
        b = random.randint(2, n//4)
        lower = k + b + 1
        upper = n - 1
        if lower > upper:
            lower = upper
        y = random.randint(lower, upper)
        x_val = h + math.sqrt((y-k)**2 / b**2 - 1) * a
        x = int(round(x_val))
        r = random.randint(2, n-2)
        s = random.randint(2, n-2)
        v = public_params.get('v', random.randint(2, n-2))
        return {'x': x, 'y': y, 'h': h, 'k': k, 'a': a, 'b': b, 'r': r, 's': s, 'v': v}
    elif challenge == '11':
        r = random.randint(2, n-2)
        s = random.randint(2, n-2)
        y = (r * s) % n
        x = random.randint(2, n-2)
        h = random.randint(1, n-1)
        k = random.randint(1, n-1)
        a = random.randint(2, n//4)
        b = random.randint(2, n//4)
        v = public_params.get('v', random.randint(2, n-2))
        return {'x': x, 'y': y, 'h': h, 'k': k, 'a': a, 'b': b, 'r': r, 's': s, 'v': v}
    else:
        raise ValueError("Invalid challenge type")

def respond_to_challenge(challenge, commitment, secret_data, public_params):
    """
    Given the challenge, commitment, and secrets, reveal only the required values for that challenge.
    """
    x = commitment['x']
    y = commitment['y']
    h = commitment['h']
    k = commitment['k']
    a = commitment['a']
    b = commitment['b']
    n = public_params['n']
    r = commitment['r']
    s = commitment['s']
    v = commitment['v']
    if challenge == '00':
        return {'y': y}
    elif challenge == '01':
        return {'x': x, 'h': h, 'k': k, 'a': a, 'b': b}
    elif challenge == '10':
        return {'y': y, 'h': h, 'k': k, 'a': a, 'b': b}
    elif challenge == '11':
        y_new = (r * s) % n
        return {'y': y_new, 'x': x, 'v': v}
    else:
        raise ValueError("Invalid challenge type")

def verify_response(challenge, commitment, response, public_params):
    """
    Given the challenge, commitment, and response, check the exact equation for that challenge.
    Returns True if valid, False otherwise.
    """
    n = public_params['n']
    if challenge == '00':
        y = response['y']
        x = commitment['x']
        return pow(y, 2, n) == x % n
    elif challenge == '01':
        x = response['x']
        h = response['h']
        k = response['k']
        a = response['a']
        b = response['b']
        y = commitment['y']
        lhs = ((x-h)**2)/(a**2) - ((y-k)**2)/(b**2)
        return math.isclose(lhs, 1.0, rel_tol=1e-9)
    elif challenge == '10':
        y = response['y']
        h = response['h']
        k = response['k']
        a = response['a']
        b = response['b']
        x = commitment['x']
        lhs = ((y-k)**2)/(b**2) - ((x-h)**2)/(a**2)
        return math.isclose(lhs, 1.0, rel_tol=1e-9)
    elif challenge == '11':
        y = response['y']
        x = response['x']
        v = response['v']
        return pow(y, 2, n) == (x * v) % n
    else:
        raise ValueError("Invalid challenge type")
