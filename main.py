# Entry point for Hypermaze Beast Mode project
# main.py

from keygen.keygen import keygen as generate_keys
from signing.sign import sign_message, SigningError
from verification.verify import verify_signature, VerificationError
import sys

def main():
    """Main function to demonstrate the Hypermaze Beast Mode signature scheme."""
    try:
        # Generate keys
        print("Generating keys...")
        private_key, public_key, exec_time = generate_keys()
        print(f"Keys generated successfully in {exec_time:.4f} seconds!")
        
        # Test message
        message = "Hello, Hypermaze Beast Mode!"
        message_bytes = message.encode()  # Convert to bytes
        
        # Test different challenge types
        challenge_types = ['00', '01', '10', '11']
        
        for challenge_type in challenge_types:
            print(f"\nTesting challenge type: {challenge_type}")
            try:
                # Sign message
                print("Signing message...")
                if challenge_type == '11':
                    signature = sign_message(message, private_key, challenge_type, public_key)
                else:
                    signature = sign_message(message, private_key, challenge_type)
                print("Message signed successfully!")
                
                # Verify signature
                print("Verifying signature...")
                is_valid = verify_signature(message_bytes, signature, public_key)
                print(f"Signature verification: {'Valid' if is_valid else 'Invalid'}")
                
            except SigningError as e:
                print(f"Error during signing: {str(e)}")
            except VerificationError as e:
                print(f"Error during verification: {str(e)}")
            except Exception as e:
                print(f"Unexpected error: {str(e)}")
                
    except Exception as e:
        print(f"Fatal error: {str(e)}")
        raise

if __name__ == "__main__":
    main()
