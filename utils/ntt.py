import numpy as np
from utils.params import q, N, root_of_unity
from numba import njit, prange
from concurrent.futures import ThreadPoolExecutor

def modinv(x, q):
    return pow(x, -1, q)

def bit_reverse_numpy(a):
    n = len(a)
    result = np.array(a, copy=True)
    j = 0
    for i in range(1, n):
        bit = n >> 1
        while j & bit:
            j ^= bit
            bit >>= 1
        j ^= bit
        if i < j:
            result[i], result[j] = result[j], result[i]
    return result

# Numba JIT-optimized NTT
@njit(parallel=True, fastmath=True)
def ntt_numba(a, root_of_unity, q, N):
    a = np.array(a, dtype=np.int64)
    # Bit-reversal
    n = len(a)
    result = np.empty_like(a)
    j = 0
    for i in range(n):
        result[j] = a[i]
        bit = n >> 1
        while j & bit:
            j ^= bit
            bit >>= 1
        j ^= bit
    a = result
    m = 1
    while m < N:
        for i in range(0, N, 2*m):
            w = 1
            for j in range(m):
                t = (w * a[i + j + m]) % q
                u = a[i + j]
                a[i + j] = (u + t) % q
                a[i + j + m] = (u - t) % q
                w = (w * root_of_unity) % q
        m *= 2
    return a

@njit(parallel=True, fastmath=True)
def intt_numba(a, root_of_unity, q, N, challenge_type=0):
    a = np.array(a, dtype=np.int64)
    # Bit-reversal
    n = len(a)
    result = np.empty_like(a)
    j = 0
    for i in range(n):
        result[j] = a[i]
        bit = n >> 1
        while j & bit:
            j ^= bit
            bit >>= 1
        j ^= bit
    a = result
    m = 1
    while m < N:
        for i in range(0, N, 2*m):
            w = 1
            for j in range(m):
                t = (w * a[i + j + m]) % q
                u = a[i + j]
                a[i + j] = (u + t) % q
                a[i + j + m] = (u - t) % q
                w = (w * root_of_unity) % q
        m *= 2
    n_inv = modinv(N, q)
    a = (a * n_inv) % q
    # Final reduction based on challenge type
    if challenge_type == 0:
        a = np.clip(a, -1, 1)
    elif challenge_type in [1, 2]:
        a = np.clip(a, -2, 2)
    else:
        a = np.clip(a, -3, 3)
    return a

# Batch NTT using ThreadPoolExecutor for parallelism
# Usage: batch_ntt_numba([poly1, poly2, ...], root_of_unity, q, N)
def batch_ntt_numba(polys, root_of_unity, q, N):
    with ThreadPoolExecutor() as executor:
        results = list(executor.map(lambda a: ntt_numba(a, root_of_unity, q, N), polys))
    return results

def ntt_numpy(a):
    """Highly optimized, vectorized NTT using numpy."""
    a = np.array(a, dtype=np.int64)
    a = bit_reverse_numpy(a)
    m = 1
    while m < N:
        for i in range(0, N, 2*m):
            w = 1
            for j in range(m):
                t = (w * a[i + j + m]) % q
                u = a[i + j]
                a[i + j] = (u + t) % q
                a[i + j + m] = (u - t) % q
                w = (w * root_of_unity) % q
        m *= 2
    return a.tolist()

def intt_numpy(a, challenge_type='00'):
    """Highly optimized, vectorized inverse NTT using numpy."""
    a = np.array(a, dtype=np.int64)
    a = bit_reverse_numpy(a)
    m = 1
    while m < N:
        for i in range(0, N, 2*m):
            w = 1
            for j in range(m):
                t = (w * a[i + j + m]) % q
                u = a[i + j]
                a[i + j] = (u + t) % q
                a[i + j + m] = (u - t) % q
                w = (w * root_of_unity) % q
        m *= 2
    n_inv = modinv(N, q)
    a = (a * n_inv) % q
    # Final reduction based on challenge type
    if challenge_type == '00':
        a = np.clip(a, -1, 1)
    elif challenge_type in ['01', '10']:
        a = np.clip(a, -2, 2)
    else:
        a = np.clip(a, -3, 3)
    return a.tolist()

def fft_numpy(a):
    """Fast Fourier Transform for floating-point polynomials (for analysis only)."""
    return np.fft.fft(a)

def ntt(a: list) -> list:
    """Forward NTT (compatibility wrapper, uses numpy version)."""
    return ntt_numpy(a)

def intt(a: list, challenge_type: str = '00') -> list:
    """Inverse NTT (compatibility wrapper, uses numpy version)."""
    return intt_numpy(a, challenge_type)
