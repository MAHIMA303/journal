from security.performance_security import PerformanceSecurity
import time
import numpy as np
import sys

def main():
    try:
        print("Starting Performance Benchmarking...")
        print("-----------------------------------")
        
        # Initialize performance security
        print("Initializing Performance Security...")
        perf_sec = PerformanceSecurity()
        
        # Run benchmarks
        print("\nRunning Operation Benchmarks...")
        print("This may take a few minutes...")
        
        start_time = time.time()
        results = perf_sec.benchmark_operations()
        total_time = time.time() - start_time
        
        if not results:
            print("❌ Benchmarking failed to produce results")
            return
            
        # Display results
        print("\nBenchmark Results:")
        print("-----------------")
        print("Operation\t\tTime (seconds)\t\tOperations/second")
        print("--------------------------------------------------------")
        
        for operation, time_taken in results.items():
            ops_per_second = 1.0 / time_taken if time_taken > 0 else 0
            print(f"{operation:20}\t{time_taken:.6f}\t\t{ops_per_second:.2f}")
        
        print(f"\nTotal Benchmark Time: {total_time:.2f} seconds")
        
        # Run security verification
        print("\nRunning Security Verification...")
        security_results = perf_sec.verify_security_strength()
        
        print("\nSecurity Verification Results:")
        print("----------------------------")
        for check, passed in security_results.items():
            status = "✓" if passed else "❌"
            print(f"{status} {check}")
        
        # Get optimization recommendations
        print("\nPerformance Optimization Recommendations:")
        print("---------------------------------------")
        optimizations = perf_sec.optimize_performance()
        
        for category, options in optimizations.items():
            print(f"\n{category}:")
            for option, enabled in options.items():
                status = "✓" if enabled else "❌"
                print(f"  {status} {option}")
                
        # Compare with competitors
        print("\nComparison with Fiat-Shamir and Falcon:")
        print("--------------------------------------")
        perf_sec._compare_with_competitors(results)
        
    except Exception as e:
        print(f"\n❌ Error during benchmarking: {str(e)}")
        print("Stack trace:")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main() 