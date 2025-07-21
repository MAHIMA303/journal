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
from challenge.four_challenges import verify_response

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

def verify_signature(message: bytes, signature: dict, public_key: dict) -> bool:
    """Verify a signature using efficient, vectorized modular arithmetic and minimal checks."""
    try:
        if not isinstance(message, bytes) or not isinstance(signature, dict) or not isinstance(public_key, dict):
            print("❌ Input validation failed")
            return False
        challenge_type = signature.get('challenge_type')
        message_hash = signature.get('message_hash')
        commitment = signature.get('commitment')
        response = signature.get('response')
        if not all([challenge_type, message_hash, commitment, response]):
            print("❌ Missing required signature components")
            return False
        computed_hash = hashlib.sha256(message).hexdigest()
        if computed_hash != message_hash:
            print("❌ Message hash verification failed")
            return False
        n = public_key['params']['q']
        public_params = {'n': n}
        if 'v' in public_key:
            public_params['v'] = public_key['v']
        # Use verify_response for the actual check
        valid = verify_response(challenge_type, commitment, response, public_params)
        if valid:
            print("✅ Signature verification passed")
        else:
            print("❌ Signature verification failed")
        return valid
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
