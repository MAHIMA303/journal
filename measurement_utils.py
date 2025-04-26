import os
import sys
import numpy as np
from typing import Dict, Tuple
from security.performance_security import PerformanceSecurity
from security.lattice_security import LatticeSecurity
from security.fiat_shamir_security import FiatShamirSecurity

class ImplementationMetrics:
    def __init__(self):
        self.perf_sec = PerformanceSecurity()
        self.lattice_sec = LatticeSecurity()
        self.fiat_sec = FiatShamirSecurity()

    def measure_signature_size(self) -> int:
        """Measure the current signature size in bytes"""
        try:
            # Create a test signature structure
            test_signature = {
                's': np.random.randint(-1, 2, size=1024),  # Example short vector
                'y_squared': np.random.randint(0, 100, size=1024),  # Example y² values
                'x_values': np.random.randint(0, 100, size=1024),  # Example x values
                'commitment_poly': np.random.randint(0, 100, size=1024),  # Example commitment
                'error': np.random.randint(-1, 2, size=1024)  # Example error term
            }
            
            # Calculate total size
            total_size = 0
            for key, value in test_signature.items():
                if isinstance(value, np.ndarray):
                    total_size += value.nbytes
                else:
                    total_size += sys.getsizeof(value)
            
            return total_size
        except Exception as e:
            print(f"Error measuring signature size: {str(e)}")
            return 0

    def measure_key_sizes(self) -> Dict[str, int]:
        """Measure the sizes of public and private keys"""
        try:
            # Create example key structures
            public_key = {
                'h_pub': np.random.randint(-1, 2, size=1024),
                'params': {
                    'N': 1024,
                    'q': 12289
                }
            }
            
            private_key = {
                'f': np.random.randint(-1, 2, size=1024),
                'g': np.random.randint(-1, 2, size=1024),
                'params': {
                    'N': 1024,
                    'q': 12289
                }
            }
            
            # Calculate sizes
            public_size = sum(sys.getsizeof(v) if not isinstance(v, np.ndarray) else v.nbytes 
                            for v in public_key.values())
            private_size = sum(sys.getsizeof(v) if not isinstance(v, np.ndarray) else v.nbytes 
                             for v in private_key.values())
            
            return {
                "public": public_size,
                "private": private_size,
                "total": public_size + private_size
            }
        except Exception as e:
            print(f"Error measuring key sizes: {str(e)}")
            return {"public": 0, "private": 0, "total": 0}

    def check_key_rotation(self) -> bool:
        """Check if key rotation is implemented"""
        try:
            # Check if key rotation methods exist
            has_rotation = (
                hasattr(self.lattice_sec, 'rotate_keys') and
                hasattr(self.fiat_sec, 'update_keys')
            )
            return has_rotation
        except:
            return False

    def check_hardware_acceleration(self) -> bool:
        """Check if hardware acceleration is implemented"""
        try:
            # Check for GPU/CPU acceleration
            has_acceleration = (
                hasattr(self.perf_sec, 'use_gpu') or
                hasattr(self.perf_sec, 'use_cpu_acceleration')
            )
            return has_acceleration
        except:
            return False

    def analyze_code_complexity(self) -> Dict[str, int]:
        """Analyze code complexity metrics"""
        metrics = {
            "total_lines": 0,
            "function_count": 0,
            "average_complexity": 0
        }
        
        try:
            # Count lines in Python files
            for root, _, files in os.walk('.'):
                for file in files:
                    if file.endswith('.py'):
                        try:
                            with open(os.path.join(root, file), 'r', encoding='utf-8') as f:
                                lines = f.readlines()
                                metrics["total_lines"] += len(lines)
                        except UnicodeDecodeError:
                            # Try with different encoding if UTF-8 fails
                            with open(os.path.join(root, file), 'r', encoding='latin-1') as f:
                                lines = f.readlines()
                                metrics["total_lines"] += len(lines)
            
            return metrics
        except Exception as e:
            print(f"Error analyzing code complexity: {str(e)}")
            return metrics

    def check_documentation(self) -> Dict[str, int]:
        """Check documentation coverage"""
        metrics = {
            "docstring_coverage": 0,
            "example_count": 0
        }
        
        try:
            # Count docstrings and examples
            for root, _, files in os.walk('.'):
                for file in files:
                    if file.endswith('.py'):
                        try:
                            with open(os.path.join(root, file), 'r', encoding='utf-8') as f:
                                content = f.read()
                                metrics["docstring_coverage"] += content.count('"""')
                                metrics["example_count"] += content.count('Example:')
                        except UnicodeDecodeError:
                            # Try with different encoding if UTF-8 fails
                            with open(os.path.join(root, file), 'r', encoding='latin-1') as f:
                                content = f.read()
                                metrics["docstring_coverage"] += content.count('"""')
                                metrics["example_count"] += content.count('Example:')
            
            return metrics
        except Exception as e:
            print(f"Error checking documentation: {str(e)}")
            return metrics

    def verify_forward_secrecy(self) -> bool:
        """Check if forward secrecy is implemented"""
        try:
            has_forward_secrecy = (
                hasattr(self.lattice_sec, 'ephemeral_keys') and
                hasattr(self.fiat_sec, 'session_keys')
            )
            return has_forward_secrecy
        except:
            return False

def get_implementation_metrics() -> Dict[str, any]:
    """Get all implementation metrics"""
    metrics = ImplementationMetrics()
    
    return {
        "signature_size": metrics.measure_signature_size(),
        "key_sizes": metrics.measure_key_sizes(),
        "has_key_rotation": metrics.check_key_rotation(),
        "has_hardware_acceleration": metrics.check_hardware_acceleration(),
        "code_complexity": metrics.analyze_code_complexity(),
        "documentation": metrics.check_documentation(),
        "has_forward_secrecy": metrics.verify_forward_secrecy()
    } 