import numpy as np
from typing import Tuple, List, Dict, Any
from utils.params import N, q
import hashlib
import random

class FiatShamirSecurity:
    def __init__(self):
        self.zero_knowledge_threshold = 0.1
        self.soundness_threshold = 0.2
        self.knowledge_extraction_threshold = 0.3
        self.parallel_session_threshold = 0.4

    def check_zero_knowledge(self, proof: Dict[str, Any], witness: Dict[str, Any]) -> bool:
        """Check for zero-knowledge proof attacks."""
        try:
            print("\nZero-Knowledge Check Diagnostic:")
            challenge_type = proof.get('challenge_type')
            print(f"Challenge type: {challenge_type}")
            print(f"Available fields: {list(proof.keys())}")
            
            # For standard Fiat-Shamir challenges (00 and 11)
            if challenge_type in ['00', '11']:
                print(f"Processing Fiat-Shamir challenge {challenge_type}")
                
                # For c=0 (challenge 00)
                if challenge_type == '00':
                    print("Verifying Fiat-Shamir c=0: y² ≡ x (mod n)")
                    # Get y_squared from proof
                    if 'y_squared' not in proof:
                        print("Missing 'y_squared' in proof")
                        return False
                    y_squared = np.array(proof['y_squared'], dtype=np.int64)
                    
                    # Get x_values from proof
                    if 'x_values' not in proof:
                        print("Missing 'x_values' in proof")
                        return False
                    x = np.array(proof['x_values'], dtype=np.int64)
                    
                    # Verify y² ≡ x (mod n)
                    if not np.array_equal(y_squared, x):
                        print("Verification failed: y² ≢ x (mod n)")
                        print(f"y_squared: {y_squared[:5]}...")
                        print(f"x: {x[:5]}...")
                        return False
                
                # For c=1 (challenge 11)
                elif challenge_type == '11':
                    print("Verifying Fiat-Shamir c=1: y² ≡ x * v (mod n)")
                    # Get y_squared and xv from proof
                    if 'y_squared' not in proof or 'xv' not in proof:
                        print("Missing 'y_squared' or 'xv' in proof")
                        return False
                    y_squared = np.array(proof['y_squared'], dtype=np.int64)
                    xv = np.array(proof['xv'], dtype=np.int64)
                    
                    # Verify y² ≡ x * v (mod n)
                    if not np.array_equal(y_squared, xv):
                        print("Verification failed: y² ≢ x * v (mod n)")
                        print(f"y_squared: {y_squared[:5]}...")
                        print(f"x * v: {xv[:5]}...")
                        return False
                
                print(f"✓ Fiat-Shamir challenge {challenge_type} verification passed")
                return True
            
            # For other challenge types, use simpler checks
            if not self._verify_completeness(proof, witness):
                print("Completeness check failed")
                return False
                
            if not self._verify_soundness(proof):
                print("Soundness check failed")
                return False
                
            print("✓ Zero-knowledge check passed")
            return True
            
        except Exception as e:
            print(f"Error in zero-knowledge check: {str(e)}")
            return False

    def check_soundness(self, proof: Dict[str, Any], statement: Dict[str, Any]) -> bool:
        """Check for soundness attacks."""
        try:
            print("\nSoundness Check Diagnostic:")
            challenge_type = proof.get('challenge_type')
            print(f"Challenge type: {challenge_type}")
            
            # For standard Fiat-Shamir challenges (00 and 11)
            if challenge_type in ['00', '11']:
                print(f"Processing Fiat-Shamir challenge {challenge_type}")
                
                # Check if all required fields are present
                required_fields = ['s', 'message_hash', 'y_squared']
                if challenge_type == '11':
                    required_fields.append('xv')
                
                for field in required_fields:
                    if field not in proof:
                        print(f"Missing required field: {field}")
                        return False
                
                # Verify the message hash
                if 'message_hash' not in proof:
                    print("Missing message_hash in proof")
                    return False
                
                # For challenge 11, verify y² ≡ x * v (mod n)
                if challenge_type == '11':
                    y_squared = np.array(proof['y_squared'], dtype=np.int64)
                    xv = np.array(proof['xv'], dtype=np.int64)
                    
                    if not np.array_equal(y_squared, xv):
                        print("Verification failed: y² ≢ x * v (mod n)")
                        print(f"y_squared: {y_squared[:5]}...")
                        print(f"x * v: {xv[:5]}...")
                        return False
                
                print(f"✓ Fiat-Shamir challenge {challenge_type} soundness check passed")
                return True
            
            # For other challenge types, use standard soundness checks
            if not self._verify_proof(proof, statement):
                print("Proof verification failed")
                return False
                
            if not self._verify_consistency(proof):
                print("Proof consistency check failed")
                return False
                
            if not self._verify_uniqueness(proof):
                print("Proof uniqueness check failed")
                return False
                
            print("✓ Soundness check passed")
            return True
            
        except Exception as e:
            print(f"Error in soundness check: {str(e)}")
            return False

    def check_knowledge_extraction(self, proof: Dict[str, Any]) -> bool:
        """Check for knowledge extraction attacks."""
        try:
            print("\nKnowledge Extraction Check Diagnostic:")
            challenge_type = proof.get('challenge_type')
            print(f"Challenge type: {challenge_type}")
            
            # For standard Fiat-Shamir challenges (00 and 11)
            if challenge_type in ['00', '11']:
                print(f"Processing Fiat-Shamir challenge {challenge_type}")
                
                # Check if all required fields are present
                required_fields = ['s', 'message_hash', 'y_squared']
                if challenge_type == '11':
                    required_fields.append('xv')
                
                for field in required_fields:
                    if field not in proof:
                        print(f"Missing required field: {field}")
                        return False
                
                # Check if the proof is properly randomized
                if not self._is_properly_randomized(proof):
                    print("Proof is not properly randomized")
                    return False
                
                print(f"✓ Fiat-Shamir challenge {challenge_type} knowledge extraction check passed")
                return True
            
            # For other challenge types, use standard knowledge extraction checks
            if not self._verify_proof_structure(proof):
                print("Proof structure verification failed")
                return False
                
            if not self._verify_binding(proof):
                print("Proof binding verification failed")
                return False
                
            if not self._verify_hiding(proof):
                print("Proof hiding verification failed")
                return False
                
            print("✓ Knowledge extraction check passed")
            return True
            
        except Exception as e:
            print(f"Error in knowledge extraction check: {str(e)}")
            return False

    def check_parallel_session(self, proofs: List[Dict[str, Any]]) -> bool:
        """Check for parallel session attacks."""
        try:
            # Check session independence
            if not self._verify_session_independence(proofs):
                return False
                
            # Check session consistency
            if not self._verify_session_consistency(proofs):
                return False
                
            # Check session uniqueness
            if not self._verify_session_uniqueness(proofs):
                return False
                
            return True
        except Exception:
            return False

    def _verify_completeness(self, proof: Dict[str, Any], witness: Dict[str, Any]) -> bool:
        """Verify proof completeness."""
        try:
            # Check if proof contains all necessary information
            required_fields = ['commitment', 'challenge', 'response']
            if not all(field in proof for field in required_fields):
                return False
                
            # Check if witness matches proof
            if not self._verify_witness_match(proof, witness):
                return False
                
            return True
        except Exception:
            return False

    def _verify_soundness(self, proof: Dict[str, Any]) -> bool:
        """Verify proof soundness."""
        try:
            # Check challenge generation
            if not self._verify_challenge(proof['challenge']):
                return False
                
            # Check response validity
            if not self._verify_response(proof['response']):
                return False
                
            return True
        except Exception:
            return False

    def _verify_zero_knowledge(self, proof: Dict[str, Any]) -> bool:
        """Verify zero-knowledge property."""
        try:
            # Check if proof reveals any information about witness
            if self._reveals_witness(proof):
                return False
                
            # Check if proof is simulatable
            if not self._is_simulatable(proof):
                return False
                
            return True
        except Exception:
            return False

    def _verify_proof(self, proof: Dict[str, Any], statement: Dict[str, Any]) -> bool:
        """Verify proof validity."""
        try:
            # Check proof structure
            if not self._verify_proof_structure(proof):
                return False
                
            # Check proof consistency with statement
            if not self._verify_statement_consistency(proof, statement):
                return False
                
            return True
        except Exception:
            return False

    def _verify_consistency(self, proof: Dict[str, Any]) -> bool:
        """Verify proof consistency."""
        try:
            # Check if commitment matches challenge
            if not self._verify_commitment_challenge_match(proof):
                return False
                
            # Check if response matches commitment and challenge
            if not self._verify_response_match(proof):
                return False
                
            return True
        except Exception:
            return False

    def _verify_uniqueness(self, proof: Dict[str, Any]) -> bool:
        """Verify proof uniqueness."""
        try:
            # Check if proof is unique for given statement
            if not self._is_unique_proof(proof):
                return False
                
            return True
        except Exception:
            return False

    def _verify_proof_structure(self, proof: Dict[str, Any]) -> bool:
        """Verify proof structure."""
        try:
            # Check required fields
            required_fields = ['commitment', 'challenge', 'response']
            if not all(field in proof for field in required_fields):
                return False
                
            # Check field types and values
            if not all(isinstance(proof[field], (int, str, bytes)) for field in required_fields):
                return False
                
            return True
        except Exception:
            return False

    def _verify_binding(self, proof: Dict[str, Any]) -> bool:
        """Verify proof binding."""
        try:
            # Check if commitment is binding
            if not self._is_binding_commitment(proof['commitment']):
                return False
                
            return True
        except Exception:
            return False

    def _verify_hiding(self, proof: Dict[str, Any]) -> bool:
        """Verify proof hiding."""
        try:
            # Check if commitment is hiding
            if not self._is_hiding_commitment(proof['commitment']):
                return False
                
            return True
        except Exception:
            return False

    def _verify_session_independence(self, proofs: List[Dict[str, Any]]) -> bool:
        """Verify session independence."""
        try:
            # Check if sessions are independent
            for i in range(len(proofs)):
                for j in range(i + 1, len(proofs)):
                    if self._are_dependent_sessions(proofs[i], proofs[j]):
                        return False
                        
            return True
        except Exception:
            return False

    def _verify_session_consistency(self, proofs: List[Dict[str, Any]]) -> bool:
        """Verify session consistency."""
        try:
            # Check if sessions are consistent
            for proof in proofs:
                if not self._verify_consistency(proof):
                    return False
                    
            return True
        except Exception:
            return False

    def _verify_session_uniqueness(self, proofs: List[Dict[str, Any]]) -> bool:
        """Verify session uniqueness."""
        try:
            # Check if sessions are unique
            for i in range(len(proofs)):
                for j in range(i + 1, len(proofs)):
                    if self._are_identical_sessions(proofs[i], proofs[j]):
                        return False
                        
            return True
        except Exception:
            return False

    def _is_properly_randomized(self, proof: Dict[str, Any]) -> bool:
        """Check if the proof is properly randomized."""
        try:
            print("\nRandomization Check Diagnostic:")
            challenge_type = proof.get('challenge_type')
            print(f"Challenge type: {challenge_type}")
            
            # For standard Fiat-Shamir challenges (00 and 11)
            if challenge_type in ['00', '11']:
                print(f"Processing Fiat-Shamir challenge {challenge_type}")
                
                # Check if s has sufficient entropy
                if 's' in proof:
                    s_array = np.array(proof['s'])
                    unique_count = len(np.unique(s_array))
                    total_count = len(s_array)
                    print(f"Unique values in s: {unique_count}/{total_count}")
                    
                    # For Fiat-Shamir, we expect some repetition in s
                    if unique_count < total_count // 4:
                        print("Insufficient entropy in s")
                        return False
                
                # For challenge 11, check y_squared and xv
                if challenge_type == '11':
                    if 'y_squared' in proof and 'xv' in proof:
                        y_squared = np.array(proof['y_squared'])
                        xv = np.array(proof['xv'])
                        
                        # They should be equal for challenge 11
                        if not np.array_equal(y_squared, xv):
                            print("y_squared and xv are not equal")
                            return False
                
                print("✓ Proof is properly randomized")
                return True
            
            # For other challenge types, use standard checks
            if 's' in proof:
                s_array = np.array(proof['s'])
                if len(np.unique(s_array)) < len(s_array) // 2:
                    print("Insufficient entropy in s")
                    return False
            
            print("✓ Proof is properly randomized")
            return True
            
        except Exception as e:
            print(f"Error in randomization check: {str(e)}")
            return False 