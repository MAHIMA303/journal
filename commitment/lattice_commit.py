# commitment/lattice_commit.py

import numpy as np
from utils.ntt import ntt, intt
from utils.params import N, q
from hash.sha_utils import shake256_hash
import matplotlib.pyplot as plt
import io
import base64

def compute_hyperbola_points(x, a, b, is_horizontal=True):
    """
    Compute points on the hyperbola based on the given parameters.
    
    For horizontal hyperbola (challenge 01):
    Equation: x²/a² - y²/b² = 1
    - a: distance from center to vertex
    - b: distance from center to co-vertex
    - x: input x-coordinate
    - Returns: (x, y) where y = ±b√(x²/a² - 1)
    
    For vertical hyperbola (challenge 10):
    Equation: y²/a² - x²/b² = 1
    - a: distance from center to vertex
    - b: distance from center to co-vertex
    - x: input x-coordinate
    - Returns: (x, y) where y = ±a√(1 + x²/b²)
    
    Security checks:
    - Ensures x²/a² > 1 for horizontal hyperbola
    - Ensures all values are within valid range
    - Handles edge cases and invalid inputs
    """
    try:
        if is_horizontal:
            # For horizontal hyperbola: x²/a² - y²/b² = 1
            if np.any(x**2 / a**2 <= 1):
                raise ValueError("x²/a² must be greater than 1 for horizontal hyperbola")
            y_squared = (x**2 / a**2 - 1) * b**2
            y = np.sqrt(y_squared)
        else:
            # For vertical hyperbola: y²/a² - x²/b² = 1
            y_squared = (1 + x**2 / b**2) * a**2
            y = np.sqrt(y_squared)
            
        # Security check: ensure values are within valid range
        if np.any(np.isnan(y)) or np.any(np.isinf(y)):
            raise ValueError("Invalid hyperbola point computation")
            
        return x, y
    except Exception as e:
        raise ValueError(f"Hyperbola point computation failed: {e}")

def compute_line_equation(point1, point2):
    """
    Compute the line equation between two points in the lattice.
    
    Parameters:
    - point1: (x1, y1) first point
    - point2: (x2, y2) second point
    
    Returns:
    - slope: m in y = mx + c
    - intercept: c in y = mx + c
    
    Security checks:
    - Validates input points
    - Handles vertical lines (infinite slope)
    - Ensures numerical stability
    """
    try:
        x1, y1 = point1
        x2, y2 = point2
        
        # Security check: validate points
        if not all(isinstance(coord, (int, float)) for coord in [x1, y1, x2, y2]):
            raise ValueError("Points must contain numeric coordinates")
            
        # Handle vertical line case
        if x2 == x1:
            return float('inf'), x1
            
        # Compute slope with numerical stability check
        slope = (y2 - y1) / (x2 - x1)
        if np.isnan(slope) or np.isinf(slope):
            raise ValueError("Invalid slope computation")
            
        intercept = y1 - slope * x1
        return slope, intercept
    except Exception as e:
        raise ValueError(f"Line equation computation failed: {e}")

def plot_hyperbola(a, b, challenge_type, private_point, public_point):
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
    
    # Save plot to bytes
    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    plt.close()
    buf.seek(0)
    return base64.b64encode(buf.getvalue()).decode('utf-8')

def create_lattice_commitment(x, y, randomness, a, b, private_key_point, public_key_point):
    """
    Create a lattice-based commitment using NTRU operations.
    Includes hyperbola points and line equation computation.
    
    Security features:
    1. Input validation
    2. Error term generation
    3. NTT-based operations
    4. Hyperbola point computation
    5. Line equation verification
    6. Multiple commitment layers
    7. Hyperbola graph visualization
    """
    try:
        # Input validation
        if not all(isinstance(arr, np.ndarray) for arr in [x, y, randomness]):
            raise ValueError("Inputs must be numpy arrays")
            
        # Convert inputs to NTT domain for faster operations
        x_ntt = ntt(x)
        y_ntt = ntt(y)
        r_ntt = ntt(randomness)
        
        # Generate small error term with security checks
        error = np.array([np.random.randint(-1, 2) for _ in range(N)])
        if not all(abs(e) <= 1 for e in error):
            raise ValueError("Invalid error term generation")
        error_ntt = ntt(error)
        
        # Compute main commitment
        commitment_ntt = [(x_ntt[i] * r_ntt[i] + y_ntt[i] + error_ntt[i]) % q for i in range(N)]
        commitment = intt(commitment_ntt)
        
        # Create binding hash
        commitment_hash = shake256_hash(str(commitment).encode())
        
        # Compute line equation with security checks
        slope, intercept = compute_line_equation(private_key_point, public_key_point)
        
        # Compute hyperbola points with security checks
        x_horiz, y_horiz = compute_hyperbola_points(x, a, b, is_horizontal=True)
        x_vert, y_vert = compute_hyperbola_points(x, a, b, is_horizontal=False)
        
        # Create hyperbola commitments
        horiz_ntt = ntt(x_horiz)
        vert_ntt = ntt(y_vert)
        
        horiz_commitment_ntt = [(horiz_ntt[i] * r_ntt[i] + error_ntt[i]) % q for i in range(N)]
        vert_commitment_ntt = [(vert_ntt[i] * r_ntt[i] + error_ntt[i]) % q for i in range(N)]
        
        horiz_commitment = intt(horiz_commitment_ntt)
        vert_commitment = intt(vert_commitment_ntt)
        
        # Generate hyperbola graphs
        horiz_graph = plot_hyperbola(a, b, '01', private_key_point, public_key_point)
        vert_graph = plot_hyperbola(a, b, '10', private_key_point, public_key_point)
        
        return {
            'commitment': commitment_hash,
            'commitment_poly': commitment,
            'x': x,
            'y': y,
            'randomness': randomness,
            'error': error,
            'a': a,
            'b': b,
            'slope': slope,
            'intercept': intercept,
            'private_key_point': private_key_point,
            'public_key_point': public_key_point,
            'horiz_hyperbola': {
                'x': x_horiz,
                'y': y_horiz,
                'commitment': horiz_commitment,
                'graph': horiz_graph
            },
            'vert_hyperbola': {
                'x': x_vert,
                'y': y_vert,
                'commitment': vert_commitment,
                'graph': vert_graph
            }
        }
    except Exception as e:
        raise ValueError(f"Failed to create lattice commitment: {e}")

def verify_lattice_commitment(commitment_data, challenge=None):
    """
    Verify a lattice-based commitment with detailed step-by-step output.
    """
    print("\n=== Starting Verification Process ===")
    print(f"Challenge: {challenge}")
    
    try:
        # Basic commitment verification
        print("\n1. Basic Commitment Verification:")
        commitment = commitment_data['commitment_poly']
        x = commitment_data['x']
        y = commitment_data['y']
        randomness = commitment_data['randomness']
        error = commitment_data['error']
        
        # Enhanced error term validation
        print("   - Checking error term bounds...")
        if not all(abs(e) <= 1 for e in error):
            print("   ❌ Error: Invalid error term bounds")
            return False
        if len(error) != N:
            print("   ❌ Error: Invalid error term length")
            return False
        print("   ✓ Error term validation passed")
        
        # Recompute and verify main commitment
        print("\n2. Main Commitment Verification:")
        x_ntt = ntt(x)
        y_ntt = ntt(y)
        r_ntt = ntt(randomness)
        error_ntt = ntt(error)
        
        expected_ntt = [(x_ntt[i] * r_ntt[i] + y_ntt[i] + error_ntt[i]) % q for i in range(N)]
        expected = intt(expected_ntt)
        
        if not np.array_equal(commitment, expected):
            print("   ❌ Error: Commitment computation mismatch")
            return False
        print("   ✓ Commitment computation verified")
        
        # Verify commitment hash
        print("\n3. Hash Verification:")
        expected_hash = shake256_hash(str(commitment).encode())
        if expected_hash != commitment_data['commitment']:
            print("   ❌ Error: Hash mismatch")
            return False
        print("   ✓ Hash verification passed")
        
        # Handle hyperbola-based challenges
        if challenge in ['01', '10']:
            print(f"\n4. Hyperbola Verification (Challenge {challenge}):")
            a = commitment_data['a']
            b = commitment_data['b']
            
            # Parameter validation
            print("   - Checking hyperbola parameters...")
            if a <= 0 or b <= 0:
                print("   ❌ Error: Invalid hyperbola parameters")
                return False
            print(f"   ✓ Parameters valid: a={a}, b={b}")
            
            if challenge == '01':
                print("\n   Horizontal Hyperbola (x²/a² - y²/b² = 1):")
                x_horiz = commitment_data['horiz_hyperbola']['x']
                y_horiz = commitment_data['horiz_hyperbola']['y']
                
                print(f"   - Revealed x: {x_horiz}")
                print(f"   - Computed y: {y_horiz}")
                
                # Verify hyperbola equation
                print("\n   - Verifying hyperbola equation...")
                lhs = x_horiz**2 / a**2 - y_horiz**2 / b**2
                print(f"   - LHS = {lhs}")
                if not np.allclose(lhs, 1, atol=1e-6):
                    print("   ❌ Error: Hyperbola equation not satisfied")
                    return False
                print("   ✓ Hyperbola equation verified")
                
                # Verify point computation
                print("\n   - Verifying point computation...")
                expected_y = np.sqrt((x_horiz**2 / a**2 - 1) * b**2)
                print(f"   - Expected y: {expected_y}")
                print(f"   - Actual y: {y_horiz}")
                if not np.allclose(y_horiz, expected_y, atol=1e-6):
                    print("   ❌ Error: Point computation mismatch")
                    return False
                print("   ✓ Point computation verified")
            else:  # challenge 10
                print("\n   Vertical Hyperbola (y²/a² - x²/b² = 1):")
                x_vert = commitment_data['vert_hyperbola']['x']
                y_vert = commitment_data['vert_hyperbola']['y']
                
                print(f"   - Revealed y: {y_vert}")
                print(f"   - Computed x: {x_vert}")
                
                # Verify hyperbola equation
                print("\n   - Verifying hyperbola equation...")
                lhs = y_vert**2 / a**2 - x_vert**2 / b**2
                print(f"   - LHS = {lhs}")
                if not np.allclose(lhs, 1, atol=1e-6):
                    print("   ❌ Error: Hyperbola equation not satisfied")
                    return False
                print("   ✓ Hyperbola equation verified")
                
                # Verify point computation
                print("\n   - Verifying point computation...")
                expected_x = np.sqrt((y_vert**2 / a**2 - 1) * b**2)
                print(f"   - Expected x: {expected_x}")
                print(f"   - Actual x: {x_vert}")
                if not np.allclose(x_vert, expected_x, atol=1e-6):
                    print("   ❌ Error: Point computation mismatch")
                    return False
                print("   ✓ Point computation verified")
            
            # Verify line equation
            print("\n5. Line Equation Verification:")
            slope = commitment_data['slope']
            intercept = commitment_data['intercept']
            private_point = commitment_data['private_key_point']
            public_point = commitment_data['public_key_point']
            
            print(f"   - Line equation: y = {slope}x + {intercept}")
            print(f"   - Private key point: {private_point}")
            print(f"   - Public key point: {public_point}")
            
            # Validate points
            print("\n   - Validating points...")
            if not all(isinstance(coord, (int, float)) for point in [private_point, public_point] for coord in point):
                print("   ❌ Error: Invalid point coordinates")
                return False
            print("   ✓ Point validation passed")
            
            # Check if points lie on the line
            print("\n   - Verifying points lie on the line...")
            if slope != float('inf'):
                expected_y_private = slope * private_point[0] + intercept
                expected_y_public = slope * public_point[0] + intercept
                print(f"   - Private point expected y: {expected_y_private}")
                print(f"   - Private point actual y: {private_point[1]}")
                print(f"   - Public point expected y: {expected_y_public}")
                print(f"   - Public point actual y: {public_point[1]}")
                
                if not (np.allclose(private_point[1], expected_y_private, atol=1e-6) and
                        np.allclose(public_point[1], expected_y_public, atol=1e-6)):
                    print("   ❌ Error: Points do not lie on the line")
                    return False
            else:
                print("   - Vertical line case")
                print(f"   - Expected x: {intercept}")
                print(f"   - Private point x: {private_point[0]}")
                print(f"   - Public point x: {public_point[0]}")
                
                if not (np.allclose(private_point[0], intercept, atol=1e-6) and
                        np.allclose(public_point[0], intercept, atol=1e-6)):
                    print("   ❌ Error: Points do not lie on the vertical line")
                    return False
            print("   ✓ Line equation verification passed")
            
        print("\n=== Verification Complete ===")
        print("✓ All checks passed")
        return True
    except Exception as e:
        print(f"\n❌ Verification error: {e}")
        return False 