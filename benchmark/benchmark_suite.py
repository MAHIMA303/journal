import time
import numpy as np
import psutil
import os
import sys
from typing import Dict, Tuple, List, Any
import matplotlib.pyplot as plt
from datetime import datetime

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class BenchmarkSuite:
    def __init__(self):
        self.results: Dict[str, List[float]] = {
            'keygen_time': [],
            'sign_time': [],
            'verify_time': [],
            'signature_size': [],
            'memory_usage': [],
            'cpu_usage': []
        }
        self.falcon_results: Dict[str, List[float]] = {
            'keygen_time': [],
            'sign_time': [],
            'verify_time': [],
            'signature_size': [],
            'memory_usage': [],
            'cpu_usage': []
        }
        self.public_key = None
        self.private_key = None

    def measure_memory(self) -> float:
        """Measure current memory usage in MB"""
        process = psutil.Process(os.getpid())
        return process.memory_info().rss / 1024 / 1024

    def measure_cpu(self) -> float:
        """Measure current CPU usage percentage"""
        return psutil.cpu_percent(interval=1)

    def benchmark_keygen(self, iterations: int = 100) -> Tuple[float, float, float]:
        """Benchmark key generation performance"""
        times = []
        memory = []
        cpu = []
        
        for _ in range(iterations):
            start_mem = self.measure_memory()
            start_cpu = self.measure_cpu()
            start_time = time.time()
            
            # Import here to avoid circular imports
            from keygen.keygen import keygen
            self.public_key, self.private_key, _ = keygen()
            
            end_time = time.time()
            end_mem = self.measure_memory()
            end_cpu = self.measure_cpu()
            
            times.append(end_time - start_time)
            memory.append(end_mem - start_mem)
            cpu.append((start_cpu + end_cpu) / 2)
        
        return np.mean(times), np.mean(memory), np.mean(cpu)

    def benchmark_signing(self, message: bytes, iterations: int = 100) -> Tuple[float, float, float, int]:
        """Benchmark signing performance"""
        if self.private_key is None:
            raise ValueError("Private key not generated. Run keygen benchmark first.")
            
        times = []
        memory = []
        cpu = []
        sizes = []
        
        for _ in range(iterations):
            start_mem = self.measure_memory()
            start_cpu = self.measure_cpu()
            start_time = time.time()
            
            # Import here to avoid circular imports
            from signing.sign import sign_message
            result = sign_message(message, self.private_key)
            signature = result['signature']
            
            end_time = time.time()
            end_mem = self.measure_memory()
            end_cpu = self.measure_cpu()
            
            times.append(end_time - start_time)
            memory.append(end_mem - start_mem)
            cpu.append((start_cpu + end_cpu) / 2)
            sizes.append(len(str(signature)))
        
        return np.mean(times), np.mean(memory), np.mean(cpu), np.mean(sizes)

    def benchmark_verification(self, message: bytes, signature: Dict[str, Any], iterations: int = 100) -> Tuple[float, float, float]:
        """Benchmark verification performance"""
        if self.public_key is None:
            raise ValueError("Public key not generated. Run keygen benchmark first.")
            
        times = []
        memory = []
        cpu = []
        
        for _ in range(iterations):
            start_mem = self.measure_memory()
            start_cpu = self.measure_cpu()
            start_time = time.time()
            
            # Import here to avoid circular imports
            from verification.verify import verify_signature
            verify_signature(message, signature, self.public_key)
            
            end_time = time.time()
            end_mem = self.measure_memory()
            end_cpu = self.measure_cpu()
            
            times.append(end_time - start_time)
            memory.append(end_mem - start_mem)
            cpu.append((start_cpu + end_cpu) / 2)
        
        return np.mean(times), np.mean(memory), np.mean(cpu)

    def run_benchmarks(self, message: bytes = b"Test message for benchmarking", iterations: int = 100):
        """Run complete benchmark suite"""
        print("\n=== Running Benchmark Suite ===")
        
        # Key Generation
        print("\nBenchmarking Key Generation...")
        keygen_time, keygen_mem, keygen_cpu = self.benchmark_keygen(iterations)
        self.results['keygen_time'].append(keygen_time)
        self.results['memory_usage'].append(keygen_mem)
        self.results['cpu_usage'].append(keygen_cpu)
        
        # Signing
        print("\nBenchmarking Signing...")
        sign_time, sign_mem, sign_cpu, sign_size = self.benchmark_signing(message, iterations)
        self.results['sign_time'].append(sign_time)
        self.results['signature_size'].append(sign_size)
        self.results['memory_usage'].append(sign_mem)
        self.results['cpu_usage'].append(sign_cpu)
        
        # Generate a signature for verification
        from signing.sign import sign_message
        signature_result = sign_message(message, self.private_key)
        signature = signature_result['signature']
        
        # Verification
        print("\nBenchmarking Verification...")
        verify_time, verify_mem, verify_cpu = self.benchmark_verification(message, signature, iterations)
        self.results['verify_time'].append(verify_time)
        self.results['memory_usage'].append(verify_mem)
        self.results['cpu_usage'].append(verify_cpu)
        
        self.generate_report()

    def generate_report(self):
        """Generate detailed benchmark report"""
        print("\n=== Benchmark Results ===")
        print(f"\nKey Generation:")
        print(f"  Time: {np.mean(self.results['keygen_time']):.6f} seconds")
        print(f"  Memory: {np.mean(self.results['memory_usage']):.2f} MB")
        print(f"  CPU: {np.mean(self.results['cpu_usage']):.2f}%")
        
        print(f"\nSigning:")
        print(f"  Time: {np.mean(self.results['sign_time']):.6f} seconds")
        print(f"  Signature Size: {np.mean(self.results['signature_size']):.2f} bytes")
        print(f"  Memory: {np.mean(self.results['memory_usage']):.2f} MB")
        print(f"  CPU: {np.mean(self.results['cpu_usage']):.2f}%")
        
        print(f"\nVerification:")
        print(f"  Time: {np.mean(self.results['verify_time']):.6f} seconds")
        print(f"  Memory: {np.mean(self.results['memory_usage']):.2f} MB")
        print(f"  CPU: {np.mean(self.results['cpu_usage']):.2f}%")
        
        self.plot_results()

    def plot_results(self):
        """Generate visualization of benchmark results"""
        plt.figure(figsize=(15, 10))
        
        # Performance plot
        plt.subplot(2, 2, 1)
        operations = ['KeyGen', 'Sign', 'Verify']
        times = [
            np.mean(self.results['keygen_time']),
            np.mean(self.results['sign_time']),
            np.mean(self.results['verify_time'])
        ]
        plt.bar(operations, times)
        plt.title('Operation Times')
        plt.ylabel('Seconds')
        
        # Memory usage plot
        plt.subplot(2, 2, 2)
        memory = [
            np.mean(self.results['memory_usage']),
            np.mean(self.results['memory_usage']),
            np.mean(self.results['memory_usage'])
        ]
        plt.bar(operations, memory)
        plt.title('Memory Usage')
        plt.ylabel('MB')
        
        # CPU usage plot
        plt.subplot(2, 2, 3)
        cpu = [
            np.mean(self.results['cpu_usage']),
            np.mean(self.results['cpu_usage']),
            np.mean(self.results['cpu_usage'])
        ]
        plt.bar(operations, cpu)
        plt.title('CPU Usage')
        plt.ylabel('Percentage')
        
        # Signature size plot
        plt.subplot(2, 2, 4)
        sizes = [0, np.mean(self.results['signature_size']), 0]
        plt.bar(operations, sizes)
        plt.title('Signature Size')
        plt.ylabel('Bytes')
        
        plt.tight_layout()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        plt.savefig(f'benchmark/results_{timestamp}.png')
        plt.close()

if __name__ == "__main__":
    benchmark = BenchmarkSuite()
    benchmark.run_benchmarks() 