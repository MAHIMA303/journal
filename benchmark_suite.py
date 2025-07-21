import time
import os
import sys
import psutil
import tracemalloc
import matplotlib.pyplot as plt
from memory_profiler import memory_usage

from keygen.keygen import keygen
from signing.sign import sign_message
from verification.verify import verify_signature

# --- Helper: Measure function run-time and memory ---
def benchmark_func(func, *args, **kwargs):
    process = psutil.Process(os.getpid())
    tracemalloc.start()
    mem_before = process.memory_info().rss / 1024**2  # in MB
    cpu_before = process.cpu_percent(interval=None)

    start = time.perf_counter()
    result = func(*args, **kwargs)
    elapsed = time.perf_counter() - start

    cpu_after = process.cpu_percent(interval=.05)
    mem_after = process.memory_info().rss / 1024**2
    peak_mem, _ = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    mem_peak = peak_mem / 1024**2

    stats = {
        'result': result,
        'time': elapsed,
        'cpu': cpu_after,
        'mem': max(mem_after, mem_peak),  # MB
        'mem_delta': max(mem_after - mem_before, mem_peak)
    }
    return stats

# --- BENCHMARK ---

print("\n[+] Benchmarking Key Generation ...")
kg_stats = benchmark_func(keygen)
secret_key, public_key, keygen_time = kg_stats['result']

sk_bytes = len(str(secret_key).encode())
pk_bytes = len(str(public_key).encode())

message = b'This is a benchmark test message'
challenge_type = '01'
print("\n[+] Benchmarking Signing ...")
sign_stats = benchmark_func(sign_message, message.decode(), secret_key, challenge_type, public_key)
signature = sign_stats['result']

print("\n[+] Benchmarking Verification ...")
verify_stats = benchmark_func(verify_signature, message, signature, public_key)

# --- PLOT ---
# Times & Memory
bench_labels = ['KeyGen', 'Sign', 'Verify']
bench_times = [kg_stats['time'], sign_stats['time'], verify_stats['time']]
bench_mems = [kg_stats['mem'], sign_stats['mem'], verify_stats['mem']]
bench_cpus = [kg_stats['cpu'], sign_stats['cpu'], verify_stats['cpu']]
key_sizes = [sk_bytes, pk_bytes]

# Bar plot
fig, axs = plt.subplots(1, 3, figsize=(16,6))

axs[0].bar(bench_labels, bench_times, color='skyblue')
axs[0].set_title('Execution Time (sec)')
axs[0].set_ylabel('Seconds')

axs[1].bar(bench_labels, bench_mems, color='salmon')
axs[1].set_title('Memory Usage (MB)')
axs[1].set_ylabel('MB')

axs[2].bar(['SecretKey', 'PublicKey'], key_sizes, color='lightgreen')
axs[2].set_title('Key Size (bytes)')
axs[2].set_ylabel('Bytes')

plt.suptitle('Lattice Signature Scheme Benchmark')
plt.tight_layout(rect=[0, 0.03, 1, 0.9])
plt.show()

# --- SUMMARY TABLE ---
print("\n===== BENCHMARK SUMMARY TABLE =====")
print("{:<14} | {:<9} | {:<9} | {:<9} | {:<15}".format("Stage","Time(s)","Mem(MB)","CPU(%)","Key Size (bytes)"))
print("-"*65)
print("{:<14} | {:<9.5f} | {:<9.4f} | {:<9.2f} | {:<15}".format(
    "KeyGen", kg_stats['time'], kg_stats['mem'], kg_stats['cpu'], sk_bytes))
print("{:<14} | {:<9.5f} | {:<9.4f} | {:<9.2f} | {:<15}".format(
    "Sign", sign_stats['time'], sign_stats['mem'], sign_stats['cpu'], "-"))
print("{:<14} | {:<9.5f} | {:<9.4f} | {:<9.2f} | {:<15}".format(
    "Verify", verify_stats['time'], verify_stats['mem'], verify_stats['cpu'], pk_bytes))
print("-"*65)
print()

# Optional: for detailed inspection:
# print(f"Secret Key Sample: {str(secret_key)[:60]} ...")
# print(f"Public Key Sample: {str(public_key)[:60]} ...")
