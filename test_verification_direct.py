# test_verification_direct.py

import numpy as np
import sys
import os
import time

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from commitment.lattice_commit import create_lattice_commitment, verify_lattice_commitment
from utils.params import N, q
from utils.ntt import ntt, intt
from hash.sha_utils import shake256_hash

def test_verification_process(challenge_type='01'):
    # Test parameters
    a = 2.0
    b = 3.0
    x = np.array([2.5] * N)  # x > a for horizontal hyperbola
    y = np.array([1.0] * N)
    randomness = np.array([1] * N)
    private_key_point = (1.0, 2.0)
    public_key_point = (3.0, 4.0)

    print(f"\n=== Testing Challenge {challenge_type} ===")
    print(f"Parameters: N={N}, q={q}\n")
    start_time = time.time()

    # Create commitment
    commitment = create_lattice_commitment(
        x, y, randomness,
        a, b,
        private_key_point, public_key_point
    )

    print("=== VERIFICATION STEPS ===")
    
    # 1. Basic commitment verification
    print("\nStep 1: Basic Commitment Verification")
    error = commitment['error']
    max_error = np.max(np.abs(error))
    print(f"Checking error term bounds...")
    print(f"Max error: {max_error}")
    print(f"Status: {'✓ PASSED' if np.all(np.abs(error) <= 1) else '❌ FAILED'}")
    
    # 2. Main commitment verification
    print("\nStep 2: Main Commitment Verification")
    print(f"Computing commitment...")
    x_ntt = ntt(x)
    y_ntt = ntt(y)
    r_ntt = ntt(randomness)
    error_ntt = ntt(error)
    computed_commitment_ntt = [(x_ntt[i] * r_ntt[i] + y_ntt[i] + error_ntt[i]) % q for i in range(N)]
    computed_commitment = intt(computed_commitment_ntt)
    print(f"Status: {'✓ PASSED' if np.array_equal(computed_commitment, commitment['commitment_poly']) else '❌ FAILED'}")
    
    # 3. Hash verification
    print("\nStep 3: Hash Verification")
    print(f"Computing commitment hash...")
    computed_hash = shake256_hash(str(computed_commitment).encode())
    print(f"Status: {'✓ PASSED' if computed_hash == commitment['commitment'] else '❌ FAILED'}")
    
    # 4. Hyperbola verification
    print(f"\nStep 4: Hyperbola Verification (Challenge {challenge_type})")
    print(f"Checking hyperbola parameters...")
    print(f"a = {a}, b = {b}")
    print(f"Parameter validation: {'✓ PASSED' if a > 0 and b > 0 else '❌ FAILED'}")
    
    if challenge_type in ['01', '10']:
        print(f"\n{'Horizontal' if challenge_type == '01' else 'Vertical'} Hyperbola:")
        x_horiz = commitment['horiz_hyperbola']['x']
        y_horiz = commitment['horiz_hyperbola']['y']
        
        print("\nVerifying hyperbola equation...")
        lhs = x_horiz**2 / a**2 - y_horiz**2 / b**2
        print(f"Status: {'✓ PASSED' if np.allclose(lhs, 1.0, atol=1e-6) else '❌ FAILED'}")
        
        print("\nVerifying point computation...")
        expected_y = np.sqrt((x_horiz**2 / a**2 - 1) * b**2)
        print(f"Status: {'✓ PASSED' if np.allclose(y_horiz, expected_y, atol=1e-6) else '❌ FAILED'}")
    
    # 5. Line equation verification
    print("\nStep 5: Line Equation Verification")
    slope = commitment['slope']
    intercept = commitment['intercept']
    print(f"Line equation: y = {slope}x + {intercept}")
    print(f"Private key point: {private_key_point}")
    print(f"Public key point: {public_key_point}")
    
    print("\nValidating points...")
    print(f"Status: {'✓ PASSED' if all(isinstance(coord, (int, float)) for point in [private_key_point, public_key_point] for coord in point) else '❌ FAILED'}")
    
    print("\nVerifying points lie on the line...")
    if slope != float('inf'):
        expected_y_private = slope * private_key_point[0] + intercept
        expected_y_public = slope * public_key_point[0] + intercept
        print(f"Status: {'✓ PASSED' if np.allclose([private_key_point[1], public_key_point[1]], [expected_y_private, expected_y_public], atol=1e-6) else '❌ FAILED'}")
    else:
        print(f"Status: {'✓ PASSED' if np.allclose([private_key_point[0], public_key_point[0]], [intercept, intercept], atol=1e-6) else '❌ FAILED'}")

    # Run actual verification
    print("\n=== FINAL VERIFICATION ===")
    result = verify_lattice_commitment(commitment, challenge=challenge_type)
    end_time = time.time()
    print(f"\nVerification time: {end_time - start_time:.6f} seconds")
    print(f"Final result: {'✓ VALID' if result else '❌ INVALID'}")
    print("="*50)

def run_all_challenges():
    print("== HYPERMAZE BEAST MODE ==")
    print("Running all challenge types:")
    
    for challenge in ['00', '01', '10', '11']:
        print(f"\n--- Challenge Type: {challenge} ---")
        test_verification_process(challenge)

if __name__ == '__main__':
    run_all_challenges() 