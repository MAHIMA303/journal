import numpy as np
from typing import Dict, List, Tuple
import matplotlib.pyplot as plt
from datetime import datetime

class SecurityAnalyzer:
    def __init__(self):
        self.results: Dict[str, float] = {}
        self.vulnerabilities: List[str] = []
        self.recommendations: List[str] = []

    def analyze_ntt_security(self) -> Tuple[float, List[str]]:
        """Analyze NTT implementation security"""
        security_score = 0.0
        issues = []
        
        try:
            from utils.ntt import ntt, intt
            from utils.params import N, q, root_of_unity
            
            # Check parameter security
            if N < 512:
                issues.append("N too small for post-quantum security")
                security_score -= 0.2
            if q < 12289:
                issues.append("Modulus q too small for security")
                security_score -= 0.2
            
            # Check root of unity properties
            if pow(root_of_unity, N, q) != 1:
                issues.append("Invalid root of unity")
                security_score -= 0.3
            
            security_score += 1.0
        except Exception as e:
            issues.append(f"NTT security check failed: {e}")
            security_score = 0.0
            
        return security_score, issues

    def analyze_key_generation(self) -> Tuple[float, List[str]]:
        """Analyze key generation security"""
        security_score = 0.0
        issues = []
        
        try:
            from keygen.keygen import AdvancedKeyGenerator
            
            # Check key generation process
            generator = AdvancedKeyGenerator()
            pk, sk, _ = generator.generate_advanced_keys()
            
            # Verify key structure
            if 'f' not in sk or 'h' not in pk:
                issues.append("Invalid key structure")
                security_score -= 0.2
            
            # Check key sizes
            if len(sk['f']) != N or len(pk['h']) != N:
                issues.append("Invalid key sizes")
                security_score -= 0.2
            
            security_score += 1.0
        except Exception as e:
            issues.append(f"Key generation security check failed: {e}")
            security_score = 0.0
            
        return security_score, issues

    def analyze_hyperbola_security(self) -> Tuple[float, List[str]]:
        """Analyze hyperbola-based verification security"""
        security_score = 0.0
        issues = []
        
        try:
            from commitment.lattice_commit import compute_hyperbola_points
            
            # Test hyperbola computation
            a, b = 2.0, 3.0
            x = np.array([2.5] * N)
            
            # Check horizontal hyperbola
            x_horiz, y_horiz = compute_hyperbola_points(x, a, b, is_horizontal=True)
            if not np.allclose(x_horiz**2/a**2 - y_horiz**2/b**2, 1, atol=1e-6):
                issues.append("Horizontal hyperbola computation error")
                security_score -= 0.2
            
            # Check vertical hyperbola
            x_vert, y_vert = compute_hyperbola_points(x, a, b, is_horizontal=False)
            if not np.allclose(y_vert**2/a**2 - x_vert**2/b**2, 1, atol=1e-6):
                issues.append("Vertical hyperbola computation error")
                security_score -= 0.2
            
            security_score += 1.0
        except Exception as e:
            issues.append(f"Hyperbola security check failed: {e}")
            security_score = 0.0
            
        return security_score, issues

    def analyze_side_channel_resistance(self) -> Tuple[float, List[str]]:
        """Analyze side-channel attack resistance"""
        security_score = 0.0
        issues = []
        
        try:
            # Check for constant-time operations
            from keygen.keygen import AdvancedKeyGenerator
            from signing.sign import sign_message
            
            # Test key generation timing
            generator = AdvancedKeyGenerator()
            times = []
            for _ in range(100):
                start = time.time()
                generator.generate_advanced_keys()
                times.append(time.time() - start)
            
            # Check timing variation
            if np.std(times) > 0.1:  # More than 100ms variation
                issues.append("Significant timing variation detected")
                security_score -= 0.3
            
            security_score += 1.0
        except Exception as e:
            issues.append(f"Side-channel resistance check failed: {e}")
            security_score = 0.0
            
        return security_score, issues

    def run_analysis(self):
        """Run complete security analysis"""
        print("\n=== Running Security Analysis ===")
        
        # NTT Security
        ntt_score, ntt_issues = self.analyze_ntt_security()
        self.results['ntt_security'] = ntt_score
        self.vulnerabilities.extend(ntt_issues)
        
        # Key Generation Security
        keygen_score, keygen_issues = self.analyze_key_generation()
        self.results['keygen_security'] = keygen_score
        self.vulnerabilities.extend(keygen_issues)
        
        # Hyperbola Security
        hyperbola_score, hyperbola_issues = self.analyze_hyperbola_security()
        self.results['hyperbola_security'] = hyperbola_score
        self.vulnerabilities.extend(hyperbola_issues)
        
        # Side Channel Resistance
        side_channel_score, side_channel_issues = self.analyze_side_channel_resistance()
        self.results['side_channel_resistance'] = side_channel_score
        self.vulnerabilities.extend(side_channel_issues)
        
        self.generate_report()

    def generate_report(self):
        """Generate detailed security analysis report"""
        print("\n=== Security Analysis Results ===")
        
        # Overall Security Score
        overall_score = np.mean(list(self.results.values()))
        print(f"\nOverall Security Score: {overall_score:.2f}/1.00")
        
        # Component Scores
        print("\nComponent Security Scores:")
        for component, score in self.results.items():
            print(f"  {component.replace('_', ' ').title()}: {score:.2f}/1.00")
        
        # Vulnerabilities
        if self.vulnerabilities:
            print("\nIdentified Vulnerabilities:")
            for vuln in self.vulnerabilities:
                print(f"  - {vuln}")
        
        # Recommendations
        print("\nSecurity Recommendations:")
        if overall_score < 0.8:
            self.recommendations.append("Implement additional security measures")
        if 'timing variation' in [v.lower() for v in self.vulnerabilities]:
            self.recommendations.append("Add constant-time implementations")
        if not self.recommendations:
            self.recommendations.append("Current security measures are adequate")
        
        for rec in self.recommendations:
            print(f"  - {rec}")
        
        self.plot_results()

    def plot_results(self):
        """Generate visualization of security analysis results"""
        plt.figure(figsize=(10, 6))
        
        components = list(self.results.keys())
        scores = list(self.results.values())
        
        plt.bar(components, scores)
        plt.title('Security Analysis Results')
        plt.ylabel('Security Score (out of 1.0)')
        plt.xticks(rotation=45)
        plt.ylim(0, 1.1)
        
        plt.tight_layout()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        plt.savefig(f'security/analysis_{timestamp}.png')
        plt.close()

if __name__ == "__main__":
    analyzer = SecurityAnalyzer()
    analyzer.run_analysis() 