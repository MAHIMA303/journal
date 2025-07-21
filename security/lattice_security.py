import numpy as np
from typing import Tuple, List
from utils.params import N, q

class LatticeSecurity:
    def __init__(self):
        self.basis_reduction_threshold = 1.0
        self.short_vector_threshold = 1000000.0
        self.closest_vector_threshold = 0.3
        self.rlwe_threshold = 0.4

    def check_lattice_basis_reduction(self, basis: np.ndarray) -> bool:
        """Check for lattice basis reduction attacks."""
        try:
            # Convert 1D array to 2D if necessary
            if len(basis.shape) == 1:
                basis = basis.reshape(1, -1)
            
            # Calculate Gram matrix
            gram_matrix = np.dot(basis, basis.T)
            
            # Calculate the determinant of the Gram matrix
            det = abs(np.linalg.det(gram_matrix))
            
            # Calculate vector norms
            norms = [np.linalg.norm(basis[i]) for i in range(basis.shape[0])]
            
            # Calculate the product of norms
            norm_product = np.prod(norms)
            
            # Calculate quality metric (similar to Hadamard ratio but works for non-square matrices)
            quality_metric = np.sqrt(det) / norm_product
            
            # Print diagnostic information
            print(f"\nLattice Basis Diagnostic:")
            print(f"Basis shape: {basis.shape}")
            print(f"Gram matrix determinant: {det}")
            print(f"Vector norms: {norms}")
            print(f"Quality metric: {quality_metric}")
            
            # For a good basis, quality_metric should be close to 1
            # We'll use a threshold of 0.5 which is reasonable for many lattice structures
            if quality_metric < 0.5:
                print(f"Quality metric {quality_metric} is below threshold 0.5")
                return False
                
            print("Lattice basis reduction check passed")
            return True
        except Exception as e:
            print(f"Error in lattice basis reduction check: {str(e)}")
            return False

    def check_short_vector(self, vector: np.ndarray, threshold: float = 1e6) -> bool:
        """Check if a vector is short enough to be a valid signature."""
        try:
            print("\nShort Vector Diagnostic:")
            # Convert to numpy array if not already
            if not isinstance(vector, np.ndarray):
                vector = np.array(vector)
            
            print(f"Vector type: {vector.dtype}")
            print(f"Vector shape: {vector.shape}")
            
            # For 1D vectors (signature vectors)
            if len(vector.shape) == 1:
                # Handle object arrays with large integers
                if vector.dtype == np.object_:
                    # First check if any value exceeds our maximum allowed value
                    max_allowed = 1e100  # Set a reasonable maximum value
                    for x in vector:
                        abs_x = abs(int(x))
                        if abs_x > max_allowed:
                            print(f"Vector contains value {abs_x} which exceeds maximum allowed value {max_allowed}")
                            return False
                    
                    # If all values are within limits, calculate norm directly
                    sum_squares = 0
                    for x in vector:
                        sum_squares += int(x) * int(x)
                    norm = np.sqrt(sum_squares)
                else:
                    # For other types, use standard calculation
                    norm = np.sqrt(np.sum(np.square(vector)))
                
                print(f"Vector norm: {norm}")
                print(f"Threshold: {threshold}")
                
                if norm > threshold:
                    print(f"Vector norm {norm} exceeds threshold {threshold}")
                    return False
                
                print("✓ Short vector check passed (1D vector)")
                return True
            
            # For 2D vectors (basis vectors)
            elif len(vector.shape) == 2:
                for i in range(vector.shape[0]):
                    basis_vector = vector[i]
                    # Handle object arrays with large integers
                    if basis_vector.dtype == np.object_:
                        # Check for maximum value
                        for x in basis_vector:
                            abs_x = abs(int(x))
                            if abs_x > max_allowed:
                                print(f"Basis vector {i} contains value {abs_x} which exceeds maximum allowed value {max_allowed}")
                                return False
                        
                        # Calculate norm if within limits
                        sum_squares = 0
                        for x in basis_vector:
                            sum_squares += int(x) * int(x)
                        norm = np.sqrt(sum_squares)
                    else:
                        norm = np.sqrt(np.sum(np.square(basis_vector)))
                    
                    if norm > threshold:
                        print(f"Basis vector {i} norm {norm} exceeds threshold {threshold}")
                        return False
                
                print("✓ Short vector check passed (2D vector)")
                return True
            
            print("❌ Invalid vector shape")
            return False
            
        except Exception as e:
            print(f"Error in short vector check: {str(e)}")
            return False

    def check_closest_vector(self, target: np.ndarray, lattice: np.ndarray) -> bool:
        """Check for closest vector problem attacks."""
        try:
            # Check distance to lattice
            distances = np.linalg.norm(lattice - target, axis=1)
            min_distance = np.min(distances)
            
            if min_distance > self.closest_vector_threshold:
                return False
                
            return True
        except Exception:
            return False

    def check_rlwe_security(self, samples: List[np.ndarray]) -> bool:
        """Check for Ring Learning with Errors attacks."""
        try:
            # Check sample distribution
            for sample in samples:
                # Check for uniform distribution
                if not self._is_uniform(sample):
                    return False
                    
                # Check for independence
                if not self._are_independent(samples):
                    return False
                    
            return True
        except Exception:
            return False

    def _is_uniform(self, sample: np.ndarray) -> bool:
        """Check if sample follows uniform distribution."""
        try:
            # Perform statistical test
            hist, _ = np.histogram(sample, bins=10)
            expected = len(sample) / 10
            chi_square = np.sum((hist - expected)**2 / expected)
            return chi_square < self.rlwe_threshold
        except Exception:
            return False

    def _are_independent(self, samples: List[np.ndarray]) -> bool:
        """Check if samples are independent."""
        try:
            # Check correlation between samples
            for i in range(len(samples)):
                for j in range(i + 1, len(samples)):
                    correlation = np.corrcoef(samples[i], samples[j])[0, 1]
                    if abs(correlation) > self.rlwe_threshold:
                        return False
            return True
        except Exception:
            return False 