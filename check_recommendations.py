import numpy as np
from improvement_tracker import ImprovementTracker
from measurement_utils import ImplementationMetrics

def check_recommendations():
    print("\n=== Checking Implementation Recommendations ===")
    
    # Initialize tracker and metrics
    tracker = ImprovementTracker()
    metrics = ImplementationMetrics()
    
    # 1. Check Signature Size
    print("\n1. Signature Size Analysis:")
    current_size = metrics.measure_signature_size()
    target_size = 666  # Falcon's size
    compression_ratio = target_size / current_size
    print(f"Current size: {current_size} bytes")
    print(f"Target size: {target_size} bytes")
    print(f"Compression needed: {compression_ratio:.2f}x")
    if current_size <= target_size:
        tracker.update_status("signature_compression", "completed")
        print("✓ Signature size meets target")
    else:
        tracker.update_status("signature_compression", "in_progress")
        print("❌ Signature size needs compression")
    
    # 2. Check Key Management
    print("\n2. Key Management Analysis:")
    has_rotation = metrics.check_key_rotation()
    if has_rotation:
        tracker.update_status("key_rotation", "completed")
        print("✓ Key rotation implemented")
    else:
        tracker.update_status("key_rotation", "not_started")
        print("❌ Key rotation not implemented")
    
    # 3. Check Hardware Support
    print("\n3. Hardware Support Analysis:")
    has_acceleration = metrics.check_hardware_acceleration()
    if has_acceleration:
        tracker.update_status("hardware_acceleration", "completed")
        print("✓ Hardware acceleration implemented")
    else:
        tracker.update_status("hardware_acceleration", "not_started")
        print("❌ Hardware acceleration not implemented")
    
    # 4. Check Code Complexity
    print("\n4. Code Complexity Analysis:")
    complexity = metrics.analyze_code_complexity()
    print(f"Total lines: {complexity['total_lines']}")
    print(f"Function count: {complexity['function_count']}")
    print(f"Average complexity: {complexity['average_complexity']}")
    if complexity['total_lines'] < 4000:  # Target is less than Falcon's 3000
        tracker.update_status("code_complexity", "completed")
        print("✓ Code complexity meets target")
    else:
        tracker.update_status("code_complexity", "in_progress")
        print("❌ Code needs simplification")
    
    # 5. Check Documentation
    print("\n5. Documentation Analysis:")
    doc_metrics = metrics.check_documentation()
    print(f"Docstring coverage: {doc_metrics['docstring_coverage']}")
    print(f"Example count: {doc_metrics['example_count']}")
    if doc_metrics['example_count'] >= 10:  # Target is at least 10 examples
        tracker.update_status("documentation", "completed")
        print("✓ Documentation meets target")
    else:
        tracker.update_status("documentation", "in_progress")
        print("❌ Documentation needs more examples")
    
    # Print overall status
    print("\n=== Overall Status ===")
    tracker.print_status_table()
    print(f"\nOverall completion: {tracker.get_completion_percentage():.1f}%")
    
    # Print next steps
    in_progress = tracker.get_in_progress_items()
    if in_progress:
        print("\nIn progress items:")
        for item in in_progress:
            print(f"- {item}")
    
    not_started = tracker.get_not_started_items()
    if not_started:
        print("\nNot started items:")
        for item in not_started:
            print(f"- {item}")

if __name__ == "__main__":
    check_recommendations() 
