import numpy as np
from typing import Dict, Any
from security.fiat_shamir_security import FiatShamirSecurity
from security.lattice_security import LatticeSecurity
from security.performance_security import PerformanceSecurity
from commitment.lattice_commit import verify_lattice_commitment

def check_result_matrix(signature: Dict[str, Any], challenge_type: str) -> bool:
    """
    Check the result matrix for a given challenge type.
    Returns True if all checks pass, False otherwise.
    """
    print(f"\n=== Checking Result Matrix for Challenge {challenge_type} ===")
    
    # Initialize security classes
    fiat_sec = FiatShamirSecurity()
    lattice_sec = LatticeSecurity()
    perf_sec = PerformanceSecurity()
    
    # 1. Check zero-knowledge properties
    print("\n1. Zero-Knowledge Check:")
    if not fiat_sec.check_zero_knowledge(signature, {}):
        print("❌ Zero-knowledge check failed")
        return False
    print("✓ Zero-knowledge check passed")
    
    # 2. Check lattice security
    print("\n2. Lattice Security Check:")
    if 's' in signature:
        if not lattice_sec.check_short_vector(np.array(signature['s'])):
            print("❌ Short vector check failed")
            return False
        print("✓ Short vector check passed")
    
    # 3. Check commitment verification
    print("\n3. Commitment Verification:")
    if not verify_lattice_commitment(signature, challenge=challenge_type):
        print("❌ Commitment verification failed")
        return False
    print("✓ Commitment verification passed")
    
    # 4. Check performance security
    print("\n4. Performance Security Check:")
    security_checks = perf_sec.verify_security_strength()
    for check, passed in security_checks.items():
        status = "✓" if passed else "❌"
        print(f"{status} {check}")
    
    if not all(security_checks.values()):
        print("❌ Some performance security checks failed")
        return False
    
    print("\n=== All Checks Passed ===")
    return True

def main():
    # Example usage
    try:
        # Load your signature data here
        signature = {
            's': [1, 0, -1, 1, 0],  # Example short vector
            'y_squared': [1, 4, 9, 16, 25],  # Example y² values
            'x_values': [1, 4, 9, 16, 25],  # Example x values
            'commitment_poly': [1, 2, 3, 4, 5],  # Example commitment
            'error': [0, 0, 0, 0, 0]  # Example error term
        }
        
        # Test all challenge types
        for challenge in ['00', '01', '10', '11']:
            print(f"\nTesting Challenge {challenge}")
            result = check_result_matrix(signature, challenge)
            print(f"Final result: {'✓ VALID' if result else '❌ INVALID'}")
            
    except Exception as e:
        print(f"Error during verification: {str(e)}")
        return False

if __name__ == "__main__":
    main() 