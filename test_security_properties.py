from challenge.four_challenges import generate_commitment, respond_to_challenge, verify_response
import random

# Use a small modulus for demo
public_params = {'n': 7919, 'v': 1234}
secret_data = {}  # Fill as needed for your protocol
challenge_types = ['00', '01', '10', '11']


def test_multi_challenge_soundness():
    print("\n=== Multi-Challenge Soundness Test ===")
    commitment = generate_commitment(secret_data, public_params)
    # Respond to two different challenges
    response_00 = respond_to_challenge('00', commitment, secret_data, public_params)
    response_01 = respond_to_challenge('01', commitment, secret_data, public_params)
    # Both should not be valid for the same commitment
    valid_00 = verify_response('00', commitment, response_00, public_params)
    valid_01 = verify_response('01', commitment, response_01, public_params)
    print(f"Challenge 00 valid: {valid_00}")
    print(f"Challenge 01 valid: {valid_01}")
    # Now try to use response_01 for challenge 00 (should fail or error)
    try:
        cross_valid = verify_response('00', commitment, response_01, public_params)
    except KeyError:
        cross_valid = False
    print(f"Cross-challenge verification (should be False): {cross_valid}")

def test_challenge_diversity_coverage():
    print("\n=== Challenge Diversity/Path Coverage Test ===")
    for ch in challenge_types:
        commitment = generate_commitment(secret_data, public_params)
        response = respond_to_challenge(ch, commitment, secret_data, public_params)
        valid = verify_response(ch, commitment, response, public_params)
        print(f"Challenge {ch} verification: {valid}")

def test_hyperbola_equation_integrity():
    print("\n=== Hyperbola Equation Integrity Test ===")
    for ch in ['01', '10']:
        commitment = generate_commitment(secret_data, public_params)
        # Forge a random response
        forged_response = {k: random.randint(1, 1000) for k in respond_to_challenge(ch, commitment, secret_data, public_params).keys()}
        valid = verify_response(ch, commitment, forged_response, public_params)
        print(f"Forged response for challenge {ch} valid (should be False): {valid}")

def test_simulatability_zero_knowledge():
    print("\n=== Simulatability/Zero-Knowledge Empirical Test ===")
    # Simulate a transcript (random values with correct structure)
    for ch in challenge_types:
        commitment = generate_commitment(secret_data, public_params)
        real_response = respond_to_challenge(ch, commitment, secret_data, public_params)
        simulated_response = {k: random.randint(1, 1000) for k in real_response.keys()}
        print(f"Challenge {ch} real response keys: {list(real_response.keys())}")
        print(f"Challenge {ch} simulated response keys: {list(simulated_response.keys())}")
        print(f"Real response: {real_response}")
        print(f"Simulated response: {simulated_response}")
        print("---")

def test_cross_challenge_consistency():
    print("\n=== Cross-Challenge Consistency Test ===")
    commitment = generate_commitment(secret_data, public_params)
    responses = {ch: respond_to_challenge(ch, commitment, secret_data, public_params) for ch in challenge_types}
    # Try to verify each response against all other challenges
    for ch1 in challenge_types:
        for ch2 in challenge_types:
            if ch1 != ch2:
                try:
                    valid = verify_response(ch1, commitment, responses[ch2], public_params)
                except KeyError:
                    valid = False
                print(f"Verify response to {ch2} as {ch1}: {valid}")

def main():
    test_multi_challenge_soundness()
    test_challenge_diversity_coverage()
    test_hyperbola_equation_integrity()
    test_simulatability_zero_knowledge()
    test_cross_challenge_consistency()

if __name__ == "__main__":
    main()
