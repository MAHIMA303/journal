# utils/params.py

N = 512  # Polynomial degree
q = 12289  # Prime modulus for NTT (same as Falcon)

# Primitive root of unity for NTT
root_of_unity = 11

# NTT requires powers of unity modulo q
modulus_poly = [1] + [0] * (N - 1) + [1]  # X^N + 1

# Gaussian sampler std dev
GAUSSIAN_STDDEV = 1.2
