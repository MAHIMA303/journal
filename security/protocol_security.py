import numpy as np
from typing import Dict, Any, List
from utils.params import N, q
import hashlib
import time

class ProtocolSecurity:
    def __init__(self):
        self.max_proof_age = 300  # 5 minutes in seconds
        self.max_parallel_sessions = 10
        self.active_sessions = {}
        
    def check_proof_freshness(self, proof: Dict[str, Any]) -> bool:
        """Check if the proof is fresh and not replayed."""
        try:
            if 'timestamp' not in proof:
                print("❌ Proof missing timestamp")
                return False
                
            current_time = time.time()
            proof_age = current_time - proof['timestamp']
            
            if proof_age > self.max_proof_age:
                print("❌ Proof too old")
                return False
                
            print("✓ Proof freshness verified")
            return True
            
        except Exception as e:
            print(f"Error in proof freshness check: {str(e)}")
            return False
            
    def check_parallel_session(self, session_id: str) -> bool:
        """Check for parallel session attacks."""
        try:
            # Clean up old sessions
            current_time = time.time()
            self.active_sessions = {
                sid: ts for sid, ts in self.active_sessions.items()
                if current_time - ts < self.max_proof_age
            }
            
            # Check if we've exceeded max parallel sessions
            if len(self.active_sessions) >= self.max_parallel_sessions:
                print("❌ Too many parallel sessions")
                return False
                
            # Add new session
            self.active_sessions[session_id] = current_time
            print("✓ Parallel session check passed")
            return True
            
        except Exception as e:
            print(f"Error in parallel session check: {str(e)}")
            return False
            
    def check_protocol_flow(self, proof: Dict[str, Any]) -> bool:
        """Verify correct protocol flow and message ordering."""
        try:
            required_fields = ['message_hash', 'challenge', 'response']
            for field in required_fields:
                if field not in proof:
                    print(f"❌ Missing required field: {field}")
                    return False
                    
            # Verify challenge-response ordering
            if 'challenge_timestamp' in proof and 'response_timestamp' in proof:
                if proof['response_timestamp'] <= proof['challenge_timestamp']:
                    print("❌ Invalid challenge-response ordering")
                    return False
                    
            print("✓ Protocol flow verified")
            return True
            
        except Exception as e:
            print(f"Error in protocol flow check: {str(e)}")
            return False
            
    def check_message_integrity(self, proof: Dict[str, Any], original_message: bytes) -> bool:
        """Verify message integrity throughout the protocol."""
        try:
            if 'message_hash' not in proof:
                print("❌ Missing message hash")
                return False
                
            computed_hash = hashlib.sha256(original_message).digest()
            if proof['message_hash'] != computed_hash:
                print("❌ Message integrity check failed")
                return False
                
            print("✓ Message integrity verified")
            return True
            
        except Exception as e:
            print(f"Error in message integrity check: {str(e)}")
            return False 