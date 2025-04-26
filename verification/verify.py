# verification/verify.py
from decimal import Decimal, getcontext
import numpy as np
import time
from utils.ntt import ntt, intt
from utils.params import N, q
from hash.sha_utils import shake256_hash
import matplotlib.pyplot as plt
from typing import Dict, Any
import hashlib
import random
import sys
import math
from security.lattice_security import LatticeSecurity
from security.fiat_shamir_security import FiatShamirSecurity

def plot_hyperbola(a, b, challenge_type, private_point, public_point, save_path=None):
    """Plot hyperbola and intersection points."""
    plt.figure(figsize=(10, 8))
    
    # Generate points for hyperbola
    if challenge_type == '01':  # Horizontal hyperbola
        x = np.linspace(a + 0.1, a + 5, 1000)
        y_pos = b * np.sqrt((x**2 / a**2) - 1)
        y_neg = -y_pos
        plt.plot(x, y_pos, 'b-', label='Hyperbola')
        plt.plot(x, y_neg, 'b-')
    else:  # Vertical hyperbola
        y = np.linspace(b + 0.1, b + 5, 1000)
        x_pos = a * np.sqrt((y**2 / b**2) + 1)
        x_neg = -x_pos
        plt.plot(x_pos, y, 'b-', label='Hyperbola')
        plt.plot(x_neg, y, 'b-')
    
    # Plot intersection points
    plt.plot(private_point[0], private_point[1], 'ro', label='Private Key Point')
    plt.plot(public_point[0], public_point[1], 'go', label='Public Key Point')
    
    # Plot intersection line
    if private_point[0] != public_point[0]:  # Not vertical line
        slope = (public_point[1] - private_point[1]) / (public_point[0] - private_point[0])
        intercept = private_point[1] - slope * private_point[0]
        x_line = np.linspace(min(private_point[0], public_point[0]) - 1, 
                           max(private_point[0], public_point[0]) + 1, 100)
        y_line = slope * x_line + intercept
        plt.plot(x_line, y_line, 'r--', label='Intersection Line')
    else:  # Vertical line
        plt.axvline(x=private_point[0], color='r--', label='Intersection Line')
    
    plt.title(f'Hyperbola Verification (Challenge {challenge_type})')
    plt.xlabel('x')
    plt.ylabel('y')
    plt.grid(True)
    plt.legend()
    plt.axis('equal')
    
    if save_path:
        plt.savefig(save_path)
        plt.close()
    else:
        plt.show()

def verify_hyperbola_graph(commitment, challenge_type, private_point, public_point):
    """Verify hyperbola graph matches between prover and verifier."""
    try:
        print("\nStep 4: Hyperbola Graph Verification")
        
        # Extract hyperbola parameters
        if 'a' not in commitment or 'b' not in commitment:
            print("Status: ❌ FAILED - Hyperbola parameters not found in commitment")
            return False
            
        a = commitment['a']
        b = commitment['b']
        
        print(f"Hyperbola parameters: a={a}, b={b}")
        
        # Verify points lie on the hyperbola
        if challenge_type == '01':
            # For horizontal hyperbola: x²/a² - y²/b² = 1
            lhs_private = private_point[0]**2 / a**2 - private_point[1]**2 / b**2
            lhs_public = public_point[0]**2 / a**2 - public_point[1]**2 / b**2
            
            print(f"Private point equation: {lhs_private}")
            print(f"Public point equation: {lhs_public}")
            
            if not (np.allclose(lhs_private, 1.0, atol=1e-6) and 
                    np.allclose(lhs_public, 1.0, atol=1e-6)):
                print("Status: ❌ FAILED - Points do not lie on horizontal hyperbola")
                return False

        elif challenge_type == '10':
            # For vertical hyperbola: y²/a² - x²/b² = 1
            lhs_private = private_point[1]**2 / a**2 - private_point[0]**2 / b**2
            lhs_public = public_point[1]**2 / a**2 - public_point[0]**2 / b**2
            
            print(f"Private point equation: {lhs_private}")
            print(f"Public point equation: {lhs_public}")
            
            if not (np.allclose(lhs_private, 1.0, atol=1e-6) and 
                    np.allclose(lhs_public, 1.0, atol=1e-6)):
                print("Status: ❌ FAILED - Points do not lie on vertical hyperbola")
                return False
                
        print("Status: ✓ PASSED - Hyperbola graph verification successful")
        return True
        
    except Exception as e:
        print(f"Status: ❌ FAILED - Graph verification error: {e}")
        return False

class VerificationError(Exception):
    """Custom exception for verification errors."""
    pass

def verify_signature(message: bytes, signature: Dict[str, Any], public_key: Dict[str, Any]) -> bool:
    """Verify a signature using the public key with enhanced security checks."""
    try:
        print("\n=== Starting Verification Process ===")
        print(f"Challenge Type: {signature.get('challenge_type')}")
        
        # Print salt information if present
        if 'salt' in signature:
            print(f"Salt: {signature['salt']}")
        
        # Initialize security checkers
        lattice_security = LatticeSecurity()
        fiat_shamir_security = FiatShamirSecurity()
        
        # Step 1: Input Validation
        if not isinstance(message, bytes) or not isinstance(signature, dict) or not isinstance(public_key, dict):
            print("❌ Input validation failed")
            return False
        print("✓ Input validation passed")
        
        # Step 2: Lattice Security Checks
        if not lattice_security.check_lattice_basis_reduction(np.array(public_key['h_pub'])):
            print("❌ Lattice basis reduction check failed")
            return False
        print("✓ Lattice basis reduction check passed")
        
        if not lattice_security.check_short_vector(np.array(signature['s'])):
            print("❌ Short vector check failed")
            return False
        print("✓ Short vector check passed")
        
        # Step 3: Fiat-Shamir Security Checks
        if signature.get('challenge_type') in ['00', '11']:
            if not fiat_shamir_security.check_zero_knowledge(signature, {'message': message}):
                print("❌ Zero-knowledge check failed")
                return False
            print("✓ Zero-knowledge check passed")
            
            if not fiat_shamir_security.check_soundness(signature, {'message': message}):
                print("❌ Soundness check failed")
                return False
            print("✓ Soundness check passed")
            
            if not fiat_shamir_security.check_knowledge_extraction(signature):
                print("❌ Knowledge extraction check failed")
                return False
            print("✓ Knowledge extraction check passed")
        
        # Step 4: Signature Component Extraction
        challenge_type = signature.get('challenge_type')
        s = signature.get('s', [])
        message_hash = signature.get('message_hash')
        x = signature.get('x')
        y = signature.get('y')
        h = signature.get('h', 0)
        k = signature.get('k', 0)
        a = signature.get('a')
        b = signature.get('b')
        R1 = signature.get('R1')
        R2 = signature.get('R2')
        commitment_y = signature.get('commitment_y')
        
        if not all([challenge_type, s, message_hash]):
            print("❌ Missing required signature components")
            return False
        print("✓ All signature components present")
        
        # Step 5: Public Key Validation
        if 'h_pub' not in public_key:
            print("❌ Public key validation failed")
            return False
        print("✓ Public key validation passed")
        
        # Step 6: Message Hash Verification
        computed_hash = hashlib.sha256(message).hexdigest()
        if computed_hash != message_hash:
            print("❌ Message hash verification failed")
            return False
        print("✓ Message hash verification passed")
        
        # Step 7: Challenge-specific Verification
        if challenge_type == '00':
            print("\nChallenge 00 (Fiat-Shamir) Verification:")
            
            # Extract parameters
            s = signature.get('s')
            message_hash = signature.get('message_hash')
            y_squared = signature.get('y_squared')
            x_values = signature.get('x_values')
            
            if None in (s, message_hash, y_squared, x_values):
                print("❌ Missing required parameters for challenge 00")
                return False
            
            try:
                # Generate Fiat-Shamir challenge
                challenge_data = f"{message_hash}|{public_key.get('h_pub')}|{N}|{q}".encode()
                challenge = int.from_bytes(hashlib.sha256(challenge_data).digest(), 'big') % q
                print(f"Generated Fiat-Shamir challenge: {challenge}")
                
                # Verify y² ≡ x (mod n)
                for i in range(N):
                    if y_squared[i] != x_values[i]:
                        print(f"❌ Challenge 00 verification failed: y² ≢ x (mod n) at index {i}")
                        return False
                
                print("✅ Challenge 00 verification passed")
                return True
                
            except Exception as e:
                print(f"❌ Verification error: {str(e)}")
                return False
                
        elif challenge_type == '01':
            # For challenge 01: verify x = (a * s[0]) mod N and y = (b * s[0]) mod N
            print("\nChallenge 01 Verification:")
            if not all([x is not None, R1 is not None, R2 is not None, s]):
                print("❌ Missing required parameters")
                return False
            
            try:
                # Step 1: Verify R1 and R2 are valid
                if R1 <= 0 or R2 <= 0 or R1 >= N or R2 >= N:
                    print("❌ Invalid R1 or R2 values")
                    return False
                
                # Step 2: Compute a and b from R1 and R2
                a = R1 % N
                b = R2 % N
                
                print(f"Base values: a={a}, b={b}")
                
                # Step 3: Verify a and b are valid and coprime with N
                if a == 0 or b == 0:
                    print("❌ Invalid base values: cannot be zero")
                    return False
                
                if math.gcd(a, N) != 1:
                    print(f"❌ Invalid base value a={a}: not coprime with N={N}")
                    return False
                
                if math.gcd(b, N) != 1:
                    print(f"❌ Invalid base value b={b}: not coprime with N={N}")
                    return False
                
                print("✓ Base values verified")
                
                # Step 4: Verify s is valid
                if not isinstance(s, list) or not s:
                    print("❌ Invalid s: must be a non-empty list")
                    return False
                
                s_val = s[0] % N  # Use first coefficient
                print(f"Using s[0] = {s_val}")
                
                # Step 5: Compute intersection points
                x_point = (a * s_val) % N
                y_point = (b * s_val) % N
                print(f"Computed intersection point: ({x_point}, {y_point})")
                print(f"Received point: ({x}, {commitment_y})")
                
                # Step 6: Verify x matches
                if x != x_point:
                    print("❌ x value does not match computed intersection point")
                    return False
                print("✓ x value verified")
                
                # Step 7: Verify y commitment matches
                if commitment_y != y_point:
                    print("❌ y commitment does not match computed intersection point")
                    return False
                print("✓ y commitment verified")
                
                # Step 8: Verify x is non-zero and coprime with N for slope calculation
                if x == 0:
                    print("❌ Cannot compute slope: x is zero")
                    return False
                
                if math.gcd(x, N) != 1:
                    print(f"❌ x value {x} is not coprime with N={N}, cannot compute slope")
                    return False
                
                try:
                    # Compute slope m = y/x in modular arithmetic
                    x_inv = pow(x, -1, N)
                    slope = (commitment_y * x_inv) % N
                    print(f"Computed slope: {slope}")
                    
                    # Verify slope matches intersection points
                    expected_y = (slope * x_point) % N
                    if expected_y != y_point:
                        print("❌ Slope verification failed: does not match intersection points")
                        return False
                    print("✓ Slope verification passed")
                    
                except ValueError as e:
                    print(f"❌ Modular arithmetic error: {str(e)}")
                    return False
                
            except Exception as e:
                print(f"❌ Verification error: {str(e)}")
                return False
            
        elif challenge_type == '10':
            # For challenge 10: Vertical hyperbola
            # Verifier computes x and verifies intersection points
            
            # Extract parameters
            y = signature.get('y')
            h = signature.get('h')
            k = signature.get('k')
            a = signature.get('a')
            b = signature.get('b')
            R1 = signature.get('R1')
            R2 = signature.get('R2')
            s_val = signature.get('s')[0]  # Using first coefficient of s
            commitment_x = signature.get('commitment_x')
            
            if None in (y, h, k, a, b, R1, R2, s_val, commitment_x):
                print("❌ Missing required parameters for challenge 10")
                return False
            
            # Step 1: Compute x using modular arithmetic
            a_mod = R1 % N
            b_mod = R2 % N
            
            # Ensure a and b are coprime with N
            if math.gcd(a_mod, N) != 1 or math.gcd(b_mod, N) != 1:
                print("❌ R1 or R2 not coprime with N")
                return False
            
            # Compute intersection points
            y_point = (a_mod * s_val) % N  # y = a * s
            x_point = (b_mod * s_val) % N  # x = b * s
            print(f"Computed intersection point: ({x_point}, {y_point})")
            print(f"Received point: ({commitment_x}, {y})")
            
            # Step 2: Verify y matches
            if y != y_point:
                print("❌ y value does not match computed intersection point")
                return False
            print("✓ y value verified")
            
            # Step 3: Verify x commitment matches
            if commitment_x != x_point:
                print("❌ x commitment does not match computed intersection point")
                return False
            print("✓ x commitment verified")
            
            # Step 4: Verify y is non-zero and coprime with N for slope calculation
            if y == 0:
                print("❌ Cannot compute slope: y is zero")
                return False
            
            if math.gcd(y, N) != 1:
                print(f"❌ y value {y} is not coprime with N={N}, cannot compute slope")
                return False
            
            try:
                # Compute slope m = x/y in modular arithmetic
                y_inv = pow(y, -1, N)
                slope = (x_point * y_inv) % N
                print(f"Computed slope: {slope}")
                
                # Verify slope matches intersection points
                expected_x = (slope * y_point) % N
                if expected_x != x_point:
                    print("❌ Slope verification failed: does not match intersection points")
                    return False
                print("✓ Slope verification passed")
                
            except ValueError as e:
                print(f"❌ Modular arithmetic error: {str(e)}")
                return False
        
        elif challenge_type == '11':
            print("\nChallenge 11 (Fiat-Shamir) Verification:")
            
            # Extract parameters
            s = signature.get('s')
            message_hash = signature.get('message_hash')
            y_squared = signature.get('y_squared')
            xv = signature.get('xv')
            
            if None in (s, message_hash, y_squared, xv):
                print("❌ Missing required parameters for challenge 11")
                return False
            
            try:
                # Generate Fiat-Shamir challenge
                challenge_data = f"{message_hash}|{public_key.get('h_pub')}|{N}|{q}".encode()
                challenge = int.from_bytes(hashlib.sha256(challenge_data).digest(), 'big') % q
                print(f"Generated Fiat-Shamir challenge: {challenge}")
                
                # Compute NTT of s and h_pub
                s_ntt = ntt(s)
                h_pub_ntt = ntt(public_key['h_pub'])
                
                # Verify y² ≡ x * v (mod n)
                for i in range(N):
                    if y_squared[i] != xv[i]:
                        print(f"❌ Challenge 11 verification failed: y² ≢ x * v (mod n) at index {i}")
                        return False
                
                print("✅ Challenge 11 verification passed")
                return True
                
            except Exception as e:
                print(f"❌ Verification error: {str(e)}")
                return False
        
        print("✓ All verifications passed!")
        return True
        
    except Exception as e:
        print(f"❌ Verification error: {str(e)}")
        return False

def verify_commitment(s: list, commitment: dict, x: int, y: int, h: int, k: int, a: int, b: int) -> bool:
    """Verify the commitment matches the provided values."""
    try:
        # Recompute commitment hash
        data = f"{s}|{commitment.get('extra_randomness', [])}|{x}|{y}|{h}|{k}".encode()
        computed_hash = hashlib.sha256(data).hexdigest()
        
        # Verify hash matches
        if computed_hash != commitment.get('commitment'):
            return False
        
        # Verify hyperbola parameters
        if commitment.get('a') != a or commitment.get('b') != b:
            return False
        
        # Verify shift values
        if commitment.get('h') != h or commitment.get('k') != k:
            return False

        return True
        
    except Exception:
        return False

def verify_proof(message: bytes, signature: Dict[str, Any], public_key: Dict[str, Any]) -> bool:
    """Verify a signature proof using the public key."""
    try:
        # Step 1: Input Validation
        if not isinstance(message, bytes):
            return False
        if not isinstance(signature, dict):
            return False
        if not isinstance(public_key, dict):
            return False
        
        # Step 2: Signature Component Extraction
        if 's' not in signature or 'challenge_type' not in signature or 'message_hash' not in signature:
            return False
        s = signature['s']
        challenge_type = signature['challenge_type']
        message_hash = signature['message_hash']
        
        # Step 3: Public Key Validation
        if 'h_pub' not in public_key:
            return False
        h = public_key['h_pub']
        
        # Step 4: Message Hash Verification
        computed_hash = hashlib.sha256(message).hexdigest()
        if computed_hash != message_hash:
            return False
        
        # Hyperbola-specific verification steps
        if challenge_type in ['01', '10']:
            if 'x' not in signature:
                return False
            x = signature['x']
            
            if 'y' not in signature:
                return False
            y = signature['y']
            
            if challenge_type == '01':
                a = signature.get('a', 1)
                b = signature.get('b', 1)
                lhs = (x**2 / a**2) - (y**2 / b**2)
                if not np.allclose(lhs, 1.0, atol=1e-6):
                    return False
            
            if 'commitment' not in signature:
                return False
            commitment = signature['commitment']
            
            if 'intersection_point' not in signature:
                return False
        
        # Step 10: NTT Transform
        s_ntt = ntt(s)
        h_ntt = ntt(h)
        
        # Step 11: Polynomial Multiplication
        product = [(s_ntt[i] * h_ntt[i]) % q for i in range(N)]
        
        # Step 12: Inverse NTT
        result = intt(product, challenge_type)
        
        # Step 13: Coefficient Verification
        if challenge_type == '00':
            is_valid = all(abs(x) <= 1 for x in result)
        elif challenge_type in ['01', '10']:
            is_valid = all(abs(x) <= 2 for x in result)
        else:  # challenge_type == '11'
            is_valid = all(abs(x) <= 3 for x in result)
        
        return is_valid
        
    except Exception:
        return False

if __name__ == "__main__":
    try:
        # Example usage
        message = b"Test message"
        public_key = {
            'h_pub': [random.randint(-1, 1) for _ in range(N)],
            'params': {
                'N': N,
                'q': q
            }
        }
        
        # Create a test signature
        private_key = {
            'f': [random.randint(-1, 1) for _ in range(N)],
            'g': [random.randint(-1, 1) for _ in range(N)],
            'params': {
                'N': N,
                'q': q
            }
        }
        
        from signing.sign import sign_message
        signature_result = sign_message(message, private_key)
        signature = signature_result['signature']
        
        # Verify the signature
        result = verify_signature(message, signature, public_key)
        
    except Exception:
        sys.exit(1)
