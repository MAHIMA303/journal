# commitment/test_verification.py

import numpy as np
from commitment.lattice_commit import create_lattice_commitment, verify_lattice_commitment
from utils.params import N
from numba import njit
from concurrent.futures import ThreadPoolExecutor

@njit
def ntt_numba(a, root_of_unity, q, N):
    # ... your NTT code here, but with all math in this function ...
    return a

def test_verification_process():
    # Test parameters
    a = 2.0
    b = 3.0
    x = np.array([2.5] * N)  # x > a for horizontal hyperbola
    y = np.array([1.0] * N)
    randomness = np.array([1] * N)
    private_key_point = (1.0, 2.0)
    public_key_point = (3.0, 4.0)

    print("\n=== Creating Commitment ===")
    print(f"Input parameters:")
    print(f"a = {a}")
    print(f"b = {b}")
    print(f"x = {x[:5]}...")  # Show first 5 elements
    print(f"y = {y[:5]}...")
    print(f"Private key point = {private_key_point}")
    print(f"Public key point = {public_key_point}")

    # Create commitment
    commitment = create_lattice_commitment(
        x, y, randomness,
        a, b,
        private_key_point, public_key_point
    )

    print("\n=== Testing Challenge 01 (Horizontal Hyperbola) ===")
    print("Verification steps:")
    
    # 1. Basic commitment verification
    print("\n1. Basic Commitment Verification:")
    print(f"Checking error term bounds...")
    error = commitment['error']
    print(f"Error term: {error[:5]}...")
    print(f"Max error: {np.max(np.abs(error))}")
    print(f"Error bounds check: {'✓ PASSED' if np.all(np.abs(error) <= 1) else '❌ FAILED'}")
    
    # 2. Main commitment verification
    print("\n2. Main Commitment Verification:")
    print(f"Computing commitment...")
    x_ntt = ntt(x)
    y_ntt = ntt(y)
    r_ntt = ntt(randomness)
    error_ntt = ntt(error)
    computed_commitment_ntt = [(x_ntt[i] * r_ntt[i] + y_ntt[i] + error_ntt[i]) % q for i in range(N)]
    computed_commitment = intt(computed_commitment_ntt)
    print(f"Computed commitment: {computed_commitment[:5]}...")
    print(f"Stored commitment: {commitment['commitment_poly'][:5]}...")
    print(f"Commitment match: {'✓ PASSED' if np.array_equal(computed_commitment, commitment['commitment_poly']) else '❌ FAILED'}")
    
    # 3. Hash verification
    print("\n3. Hash Verification:")
    print(f"Computing commitment hash...")
    computed_hash = shake256_hash(str(computed_commitment).encode())
    print(f"Computed hash: {computed_hash[:16]}...")
    print(f"Stored hash: {commitment['commitment'][:16]}...")
    print(f"Hash match: {'✓ PASSED' if computed_hash == commitment['commitment'] else '❌ FAILED'}")
    
    # 4. Hyperbola verification
    print("\n4. Hyperbola Verification (Challenge 01):")
    print(f"Checking hyperbola parameters...")
    print(f"a = {a}, b = {b}")
    print(f"Parameter validation: {'✓ PASSED' if a > 0 and b > 0 else '❌ FAILED'}")
    
    print("\nHorizontal Hyperbola (x²/a² - y²/b² = 1):")
    x_horiz = commitment['horiz_hyperbola']['x']
    y_horiz = commitment['horiz_hyperbola']['y']
    print(f"Revealed x: {x_horiz[:5]}...")
    print(f"Computed y: {y_horiz[:5]}...")
    
    print("\nVerifying hyperbola equation...")
    lhs = x_horiz**2 / a**2 - y_horiz**2 / b**2
    print(f"LHS = {lhs[:5]}...")
    print(f"Expected value = 1.0")
    print(f"Equation verification: {'✓ PASSED' if np.allclose(lhs, 1.0, atol=1e-6) else '❌ FAILED'}")
    
    print("\nVerifying point computation...")
    expected_y = np.sqrt((x_horiz**2 / a**2 - 1) * b**2)
    print(f"Expected y: {expected_y[:5]}...")
    print(f"Actual y: {y_horiz[:5]}...")
    print(f"Point computation: {'✓ PASSED' if np.allclose(y_horiz, expected_y, atol=1e-6) else '❌ FAILED'}")
    
    # 5. Line equation verification
    print("\n5. Line Equation Verification:")
    slope = commitment['slope']
    intercept = commitment['intercept']
    print(f"Line equation: y = {slope}x + {intercept}")
    print(f"Private key point: {private_key_point}")
    print(f"Public key point: {public_key_point}")
    
    print("\nValidating points...")
    print(f"Point validation: {'✓ PASSED' if all(isinstance(coord, (int, float)) for point in [private_key_point, public_key_point] for coord in point) else '❌ FAILED'}")
    
    print("\nVerifying points lie on the line...")
    if slope != float('inf'):
        expected_y_private = slope * private_key_point[0] + intercept
        expected_y_public = slope * public_key_point[0] + intercept
        print(f"Private point expected y: {expected_y_private}")
        print(f"Private point actual y: {private_key_point[1]}")
        print(f"Public point expected y: {expected_y_public}")
        print(f"Public point actual y: {public_key_point[1]}")
        print(f"Line verification: {'✓ PASSED' if np.allclose([private_key_point[1], public_key_point[1]], [expected_y_private, expected_y_public], atol=1e-6) else '❌ FAILED'}")
    else:
        print("Vertical line case")
        print(f"Expected x: {intercept}")
        print(f"Private point x: {private_key_point[0]}")
        print(f"Public point x: {public_key_point[0]}")
        print(f"Line verification: {'✓ PASSED' if np.allclose([private_key_point[0], public_key_point[0]], [intercept, intercept], atol=1e-6) else '❌ FAILED'}")

    # Run actual verification
    print("\n=== Running Full Verification ===")
    result = verify_lattice_commitment(commitment, challenge='01')
    print(f"\nFinal result: {'✓ VALID' if result else '❌ INVALID'}")

    print("\n=== Testing Challenge 10 (Vertical Hyperbola) ===")
    print("Expected output format:")
    print("""
=== Starting Verification Process ===
Challenge: 10

1. Basic Commitment Verification:
   - Checking error term bounds...
   ✓ Error term validation passed

2. Main Commitment Verification:
   ✓ Commitment computation verified

3. Hash Verification:
   ✓ Hash verification passed

4. Hyperbola Verification (Challenge 10):
   - Checking hyperbola parameters...
   ✓ Parameters valid: a=2.0, b=3.0

   Vertical Hyperbola (y²/a² - x²/b² = 1):
   - Revealed y: [3.0, 3.0, ...]
   - Computed x: [2.0, 2.0, ...]

   - Verifying hyperbola equation...
   - LHS = 1.0
   ✓ Hyperbola equation verified

   - Verifying point computation...
   - Expected x: [2.0, 2.0, ...]
   - Actual x: [2.0, 2.0, ...]
   ✓ Point computation verified

5. Line Equation Verification:
   - Line equation: y = 1.0x + 1.0
   - Private key point: (1.0, 2.0)
   - Public key point: (3.0, 4.0)

   - Validating points...
   ✓ Point validation passed

   - Verifying points lie on the line...
   - Private point expected y: 2.0
   - Private point actual y: 2.0
   - Public point expected y: 4.0
   - Public point actual y: 4.0
   ✓ Line equation verification passed

=== Verification Complete ===
✓ All checks passed
""")

    # Run actual verification
    print("\nActual verification output:")
    result = verify_lattice_commitment(commitment, challenge='10')
    print(f"\nFinal result: {'✓ VALID' if result else '❌ INVALID'}")

if __name__ == '__main__':
    test_verification_process() 