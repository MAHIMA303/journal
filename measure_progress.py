import json
from datetime import datetime
from measurement_utils import get_implementation_metrics
from improvement_tracker import ImprovementTracker

def update_tracker_with_metrics(tracker: ImprovementTracker, metrics: dict):
    """Update the improvement tracker with current metrics"""
    # Update signature size requirement
    current_size = metrics["signature_size"]
    target_size = 1024  # 1KB target
    if current_size <= target_size:
        tracker.update_status("signature_compression", "completed")
    else:
        tracker.update_status("signature_compression", "in_progress")

    # Update key rotation requirement
    if metrics["has_key_rotation"]:
        tracker.update_status("key_rotation", "completed")
    else:
        tracker.update_status("key_rotation", "not_started")

    # Update key storage requirement
    total_key_size = metrics["key_sizes"]["total"]
    if total_key_size <= 2048:  # 2KB target
        tracker.update_status("key_storage", "completed")
    else:
        tracker.update_status("key_storage", "in_progress")

    # Update hardware acceleration requirement
    if metrics["has_hardware_acceleration"]:
        tracker.update_status("hardware_acceleration", "completed")
    else:
        tracker.update_status("hardware_acceleration", "not_started")

    # Update documentation requirement
    doc_metrics = metrics["documentation"]
    if doc_metrics["docstring_coverage"] >= 10 and doc_metrics["example_count"] >= 5:
        tracker.update_status("documentation", "completed")
    else:
        tracker.update_status("documentation", "in_progress")

    # Update forward secrecy requirement
    if metrics["has_forward_secrecy"]:
        tracker.update_status("forward_secrecy", "completed")
    else:
        tracker.update_status("forward_secrecy", "not_started")

def main():
    # Initialize tracker
    tracker = ImprovementTracker()
    
    # Get current metrics
    print("Measuring implementation metrics...")
    metrics = get_implementation_metrics()
    
    # Update tracker
    print("Updating improvement tracker...")
    update_tracker_with_metrics(tracker, metrics)
    
    # Print current status
    print("\nCurrent Implementation Status:")
    print("=" * 50)
    print(f"Signature Size: {metrics['signature_size']} bytes")
    print(f"Key Sizes: {metrics['key_sizes']}")
    print(f"Code Complexity: {metrics['code_complexity']}")
    print(f"Documentation: {metrics['documentation']}")
    print("\nImprovement Progress:")
    print("=" * 50)
    tracker.print_status_table()

if __name__ == "__main__":
    main() 