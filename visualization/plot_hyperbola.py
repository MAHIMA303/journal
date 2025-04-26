import numpy as np
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle

def plot_hyperbola(a, b, challenge_type, ax=None):
    """Plot hyperbola based on challenge type and parameters."""
    if ax is None:
        ax = plt.gca()
    
    # Generate points
    x = np.linspace(-10, 10, 1000)
    
    if challenge_type in ['01', '10']:
        # Horizontal hyperbola: (x^2/a^2) - (y^2/b^2) = 1
        y_pos = b * np.sqrt((x**2/a**2) - 1)
        y_neg = -b * np.sqrt((x**2/a**2) - 1)
        # Plot only where x^2/a^2 > 1
        mask = x**2/a**2 > 1
        ax.plot(x[mask], y_pos[mask], 'b-', label=f'Challenge {challenge_type}')
        ax.plot(x[mask], y_neg[mask], 'b-')
    else:  # '00' or '11'
        # Vertical hyperbola: (y^2/a^2) - (x^2/b^2) = 1
        y = np.linspace(-10, 10, 1000)
        x_pos = b * np.sqrt((y**2/a**2) - 1)
        x_neg = -b * np.sqrt((y**2/a**2) - 1)
        # Plot only where y^2/a^2 > 1
        mask = y**2/a**2 > 1
        ax.plot(x_pos[mask], y[mask], 'r-', label=f'Challenge {challenge_type}')
        ax.plot(x_neg[mask], y[mask], 'r-')

    # Add grid and labels
    ax.grid(True)
    ax.set_xlabel('x')
    ax.set_ylabel('y')
    ax.set_title(f'Hyperbola for Challenge {challenge_type}')
    ax.legend()
    ax.axis('equal')

def main():
    # Create a figure with 2x2 subplots
    fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 15))
    
    # Example parameters
    a, b = 2.0, 3.0
    
    # Plot different challenge types
    plot_hyperbola(a, b, '00', ax1)
    plot_hyperbola(a, b, '01', ax2)
    plot_hyperbola(a, b, '10', ax3)
    plot_hyperbola(a, b, '11', ax4)
    
    plt.tight_layout()
    plt.savefig('visualization/hyperbolas.png')
    plt.close()

if __name__ == "__main__":
    main() 