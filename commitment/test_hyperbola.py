# commitment/test_hyperbola.py

import unittest
import numpy as np
from commitment.lattice_commit import (
    compute_hyperbola_points,
    compute_line_equation,
    create_lattice_commitment,
    verify_lattice_commitment
)
from utils.params import N

class TestHyperbolaChallenges(unittest.TestCase):
    def setUp(self):
        # Test parameters
        self.a = 2.0
        self.b = 3.0
        self.x = np.array([2.5] * N)  # x > a for horizontal hyperbola
        self.y = np.array([1.0] * N)
        self.randomness = np.array([1] * N)
        self.private_key_point = (1.0, 2.0)
        self.public_key_point = (3.0, 4.0)

    def test_horizontal_hyperbola(self):
        """Test horizontal hyperbola (challenge 01) point computation"""
        x, y = compute_hyperbola_points(self.x, self.a, self.b, is_horizontal=True)
        
        # Verify hyperbola equation: x²/a² - y²/b² = 1
        lhs = x**2 / self.a**2 - y**2 / self.b**2
        self.assertTrue(np.allclose(lhs, 1, atol=1e-6))
        
        # Verify y computation
        expected_y = np.sqrt((x**2 / self.a**2 - 1) * self.b**2)
        self.assertTrue(np.allclose(y, expected_y, atol=1e-6))

    def test_vertical_hyperbola(self):
        """Test vertical hyperbola (challenge 10) point computation"""
        x, y = compute_hyperbola_points(self.x, self.a, self.b, is_horizontal=False)
        
        # Verify hyperbola equation: y²/a² - x²/b² = 1
        lhs = y**2 / self.a**2 - x**2 / self.b**2
        self.assertTrue(np.allclose(lhs, 1, atol=1e-6))
        
        # Verify y computation
        expected_y = np.sqrt((1 + x**2 / self.b**2) * self.a**2)
        self.assertTrue(np.allclose(y, expected_y, atol=1e-6))

    def test_line_equation(self):
        """Test line equation computation between points"""
        slope, intercept = compute_line_equation(self.private_key_point, self.public_key_point)
        
        # Verify points lie on the line
        x1, y1 = self.private_key_point
        x2, y2 = self.public_key_point
        
        if slope != float('inf'):
            self.assertAlmostEqual(y1, slope * x1 + intercept)
            self.assertAlmostEqual(y2, slope * x2 + intercept)
        else:
            self.assertAlmostEqual(x1, intercept)
            self.assertAlmostEqual(x2, intercept)

    def test_commitment_creation(self):
        """Test commitment creation with hyperbola points"""
        commitment = create_lattice_commitment(
            self.x, self.y, self.randomness,
            self.a, self.b,
            self.private_key_point, self.public_key_point
        )
        
        # Verify commitment structure
        self.assertIn('commitment', commitment)
        self.assertIn('horiz_hyperbola', commitment)
        self.assertIn('vert_hyperbola', commitment)
        self.assertIn('slope', commitment)
        self.assertIn('intercept', commitment)

    def test_commitment_verification(self):
        """Test commitment verification for different challenges"""
        commitment = create_lattice_commitment(
            self.x, self.y, self.randomness,
            self.a, self.b,
            self.private_key_point, self.public_key_point
        )
        
        # Test challenge 00 (standard Fiat-Shamir)
        self.assertTrue(verify_lattice_commitment(commitment, challenge='00'))
        
        # Test challenge 01 (horizontal hyperbola)
        self.assertTrue(verify_lattice_commitment(commitment, challenge='01'))
        
        # Test challenge 10 (vertical hyperbola)
        self.assertTrue(verify_lattice_commitment(commitment, challenge='10'))
        
        # Test challenge 11 (standard Fiat-Shamir)
        self.assertTrue(verify_lattice_commitment(commitment, challenge='11'))

    def test_invalid_inputs(self):
        """Test handling of invalid inputs"""
        # Test invalid hyperbola parameters
        with self.assertRaises(ValueError):
            compute_hyperbola_points(self.x, -1.0, self.b, is_horizontal=True)
        
        # Test invalid points for line equation
        with self.assertRaises(ValueError):
            compute_line_equation((1, 'invalid'), self.public_key_point)
        
        # Test invalid commitment parameters
        with self.assertRaises(ValueError):
            create_lattice_commitment(
                self.x, self.y, self.randomness,
                -1.0, self.b,
                self.private_key_point, self.public_key_point
            )

    def test_edge_cases(self):
        """Test edge cases in hyperbola computation"""
        # Test x = a (should fail for horizontal hyperbola)
        x_edge = np.array([self.a] * N)
        with self.assertRaises(ValueError):
            compute_hyperbola_points(x_edge, self.a, self.b, is_horizontal=True)
        
        # Test vertical line
        slope, intercept = compute_line_equation((1.0, 2.0), (1.0, 3.0))
        self.assertEqual(slope, float('inf'))
        self.assertEqual(intercept, 1.0)

if __name__ == '__main__':
    unittest.main() 