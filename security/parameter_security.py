import numpy as np
from typing import Dict, Any, List
from utils.params import N, q
import math

class ParameterSecurity:
    def __init__(self):
        self.min_poly_degree = 256
        self.max_poly_degree = 1024
        self.min_modulus_bits = 2048
        self.max_modulus_bits = 4096
        self.min_entropy = 128
        self.max_coefficient = 2**32
        
    def check_polynomial_parameters(self, poly: np.ndarray) -> bool:
        """Verify polynomial parameters are secure."""
        try:
            # Check degree
            if len(poly) < self.min_poly_degree or len(poly) > self.max_poly_degree:
                print(f"❌ Invalid polynomial degree: {len(poly)}")
                return False
                
            # Check coefficient bounds
            max_coeff = np.max(np.abs(poly))
            if max_coeff > self.max_coefficient:
                print(f"❌ Coefficients too large: {max_coeff}")
                return False
                
            # Check entropy
            unique_coeffs = len(np.unique(poly))
            if unique_coeffs < 2**self.min_entropy:
                print(f"❌ Insufficient entropy: {unique_coeffs} unique coefficients")
                return False
                
            print("✓ Polynomial parameters verified")
            return True
            
        except Exception as e:
            print(f"Error in polynomial parameter check: {str(e)}")
            return False
            
    def check_modulus_parameters(self, modulus: int) -> bool:
        """Verify modulus parameters are secure."""
        try:
            # Check bit length
            bits = math.ceil(math.log2(modulus))
            if bits < self.min_modulus_bits or bits > self.max_modulus_bits:
                print(f"❌ Invalid modulus bit length: {bits}")
                return False
                
            # Check if modulus is prime
            if not self._is_prime(modulus):
                print("❌ Modulus is not prime")
                return False
                
            print("✓ Modulus parameters verified")
            return True
            
        except Exception as e:
            print(f"Error in modulus parameter check: {str(e)}")
            return False
            
    def _is_prime(self, n: int) -> bool:
        """Miller-Rabin primality test."""
        if n < 2:
            return False
        for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]:
            if n % p == 0:
                return n == p
        d = n - 1
        s = 0
        while d % 2 == 0:
            d //= 2
            s += 1
        for a in [2, 325, 9375, 28178, 450775, 9780504, 1795265022]:
            if a >= n:
                continue
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(s - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True
        
    def check_parameter_relationships(self, params: Dict[str, Any]) -> bool:
        """Verify relationships between different parameters."""
        try:
            # Check polynomial degree vs modulus size
            if 'poly_degree' in params and 'modulus_bits' in params:
                if params['poly_degree'] * 2 > params['modulus_bits']:
                    print("❌ Polynomial degree too large for modulus")
                    return False
                    
            # Check coefficient bounds vs modulus
            if 'max_coeff' in params and 'modulus' in params:
                if params['max_coeff'] * 2 >= params['modulus']:
                    print("❌ Coefficients too large for modulus")
                    return False
                    
            print("✓ Parameter relationships verified")
            return True
            
        except Exception as e:
            print(f"Error in parameter relationship check: {str(e)}")
            return False 