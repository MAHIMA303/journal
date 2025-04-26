# Placeholder for commit.py
# commitment/commit.py

from commitment.lattice_commit import create_lattice_commitment, verify_lattice_commitment
from utils.params import N
import numpy as np

def create_commitment(x, y, randomness, a, b, private_key_point, public_key_point):
    """
    Create a commitment using lattice-based operations.
    Includes hyperbola points and line equation computation.
    """
    # Ensure inputs are numpy arrays of correct length
    x = np.array(x)
    y = np.array(y)
    randomness = np.array(randomness)
    
    if len(x) != N or len(y) != N or len(randomness) != N:
        raise ValueError("Input vectors must have length N")
        
    # Ensure a and b are positive
    if a <= 0 or b <= 0:
        raise ValueError("Hyperbola parameters a and b must be positive")
        
    # Ensure points are valid
    if not isinstance(private_key_point, tuple) or not isinstance(public_key_point, tuple):
        raise ValueError("Points must be tuples")
    if len(private_key_point) != 2 or len(public_key_point) != 2:
        raise ValueError("Points must have exactly 2 coordinates")
        
    return create_lattice_commitment(x, y, randomness, a, b, private_key_point, public_key_point)

def verify_commitment(commitment_data, x=None, y=None, challenge=None):
    """
    Verify a commitment using lattice-based operations.
    For challenges 01 and 10, verifies hyperbola conditions and line equation.
    """
    if not verify_lattice_commitment(commitment_data, challenge):
        return False
        
    # If specific values are provided, verify against them
    if x is not None and not np.array_equal(commitment_data['x'], x):
        return False
    if y is not None and not np.array_equal(commitment_data['y'], y):
        return False
        
    # For hyperbola-based challenges, verify the revealed coordinate
    if challenge in ['01', '10']:
        a = commitment_data['a']
        b = commitment_data['b']
        
        if challenge == '01':
            # For horizontal hyperbola, verify x coordinate
            x_horiz = commitment_data['horiz_hyperbola']['x']
            if x is not None and not np.array_equal(x_horiz, x):
                return False
        else:  # challenge 10
            # For vertical hyperbola, verify y coordinate
            y_vert = commitment_data['vert_hyperbola']['y']
            if y is not None and not np.array_equal(y_vert, y):
                return False
            
        # Verify line equation points
        slope = commitment_data['slope']
        intercept = commitment_data['intercept']
        private_point = commitment_data['private_key_point']
        public_point = commitment_data['public_key_point']
        
        # Check if points lie on the line
        if slope != float('inf'):
            expected_y_private = slope * private_point[0] + intercept
            expected_y_public = slope * public_point[0] + intercept
            if not (np.allclose(private_point[1], expected_y_private, atol=1e-6) and
                    np.allclose(public_point[1], expected_y_public, atol=1e-6)):
                return False
        else:
            if not (np.allclose(private_point[0], intercept, atol=1e-6) and
                    np.allclose(public_point[0], intercept, atol=1e-6)):
                return False
            
    return True
