# Placeholder for ntt.py
# utils/ntt.py

from utils.params import q, N, root_of_unity

def modinv(x, q):
    return pow(x, -1, q)

def bit_reverse(a):
    n = len(a)
    j = 0
    for i in range(1, n):
        bit = n >> 1
        while j & bit:
            j ^= bit
            bit >>= 1
        j ^= bit
        if i < j:
            a[i], a[j] = a[j], a[i]
    return a

def ntt(a: list) -> list:
    """Forward NTT with proper coefficient reduction."""
    if not isinstance(a, list) or len(a) != N:
        raise ValueError("Invalid input polynomial")
    
    a = bit_reverse(a)
    m = 1
    while m < N:
        for i in range(0, N, 2*m):
            w = 1
            for j in range(m):
                t = w * a[i + j + m]
                # Reduce t immediately after multiplication
                if t > q//2:
                    t -= q
                elif t < -q//2:
                    t += q
                
                u = a[i + j]
                a[i + j] = u + t
                a[i + j + m] = u - t
                
                # Reduce coefficients after addition/subtraction
                if a[i + j] > q//2:
                    a[i + j] -= q
                elif a[i + j] < -q//2:
                    a[i + j] += q
                    
                if a[i + j + m] > q//2:
                    a[i + j + m] -= q
                elif a[i + j + m] < -q//2:
                    a[i + j + m] += q
                
                w = w * root_of_unity
                # Reduce w after multiplication
                if w > q//2:
                    w -= q
                elif w < -q//2:
                    w += q
        m *= 2
    return a

def intt(a: list, challenge_type: str = '00') -> list:
    """Inverse NTT with proper coefficient reduction based on challenge type."""
    if not isinstance(a, list) or len(a) != N:
        raise ValueError("Invalid input polynomial")
    
    a = bit_reverse(a)
    m = 1
    while m < N:
        for i in range(0, N, 2*m):
            w = 1
            for j in range(m):
                t = w * a[i + j + m]
                # Reduce t immediately after multiplication
                t = t % q
                if t > q//2:
                    t -= q
                
                u = a[i + j]
                a[i + j] = (u + t) % q
                a[i + j + m] = (u - t) % q
                
                # Reduce coefficients after addition/subtraction
                if a[i + j] > q//2:
                    a[i + j] -= q
                if a[i + j + m] > q//2:
                    a[i + j + m] -= q
                
                w = (w * root_of_unity) % q
                if w > q//2:
                    w -= q
        m *= 2
    
    # Final reduction based on challenge type
    n_inv = modinv(N, q)
    result = []
    for i in range(N):
        val = (a[i] * n_inv) % q
        if val > q//2:
            val -= q
        
        # Strict reduction based on challenge type
        if challenge_type == '00':
            while val > 1:
                val -= q
            while val < -1:
                val += q
        elif challenge_type in ['01', '10']:
            while val > 2:
                val -= q
            while val < -2:
                val += q
        else:  # challenge_type == '11'
            while val > 3:
                val -= q
            while val < -3:
                val += q
        
        result.append(val)
    return result
