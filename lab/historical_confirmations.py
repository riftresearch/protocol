"""
This script calculates the probability of mining a certain number of blocks in a certain amount of time.
Those times are collected from the block_analysis.py script which analyzes 800k blocks and determines the 
maximum time to mine a certain number of sequential blocks.
"""

from scipy.stats import gamma
from block_analysis import get_associated_time_to_mines

# Parameters
scale = 10  # Scale (θ) = average time per block (minutes)
shape = 2 
max_times = 4*60

# CDF
probability = gamma.cdf(max_times, a=shape, scale=scale)
print(f"[CDF] Probability of {shape} block/s mining in {max_times:.2f} minutes: {probability*100:.10f}%")

# Parameters
scale = 10  # Scale (θ) = average time per block (minutes)
search_ranges = range(1, 255)
shape = list(search_ranges) # Shape (k) = num blocks 
max_times = [max_time / 60 for block_range, max_time in get_associated_time_to_mines(windows=search_ranges)[0].items()]

# CDF
probabilities = []
for i in range(len(shape)):
    probability = gamma.cdf(max_times[i], a=shape[i], scale=scale)
    probabilities.append(probability)
    print(f"[CDF] Probability of {shape[i]} block/s mining in {max_times[i]:.2f} minutes: {probability*100:.10f}%")

# ----------------------------------------
# Add-on: fit line & quadratic, graph them
# ----------------------------------------
import numpy as np
import matplotlib.pyplot as plt

# Convert the lists you already built
blocks = np.array(shape, dtype=float)        #  n  (1 … 254)
minutes = np.array(max_times, dtype=float)   #  t(n)

# ----- linear (degree-1) fit -----
lin_coeff = np.polyfit(blocks, minutes, 1)   # [slope, intercept]
lin_fit   = np.poly1d(lin_coeff)
lin_pred  = lin_fit(blocks)

# ----- quadratic (degree-2) fit -----
quad_coeff = np.polyfit(blocks, minutes, 2)  # [a, b, c]  for  a n² + b n + c
quad_fit   = np.poly1d(quad_coeff)
quad_pred  = quad_fit(blocks)

# ----- R² for each model -----
ss_tot   = np.sum((minutes - minutes.mean())**2)
r2_lin   = 1 - np.sum((minutes - lin_pred )**2) / ss_tot
r2_quad  = 1 - np.sum((minutes - quad_pred)**2) / ss_tot

print("\n--- Fits on max-time data -------------------------------------")
print("Linear :  t(n) ≈ {:.4f}·n  + {:.4f}     (R² = {:.4f})"
      .format(lin_coeff[0], lin_coeff[1], r2_lin))
print("Quadrat:  t(n) ≈ {:.6f}·n² + {:.4f}·n + {:.4f}  (R² = {:.4f})"
      .format(quad_coeff[0], quad_coeff[1], quad_coeff[2], r2_quad))

# ----- plot -----
plt.figure(figsize=(8, 5))
plt.scatter(blocks, minutes,  color='tab:orange', label='data', s=20)
plt.plot(blocks, lin_pred,   label=f'linear fit  (R²≈{r2_lin:.3f})')
plt.plot(blocks, quad_pred,  label=f'quadratic fit (R²≈{r2_quad:.3f})')
plt.xlabel('Blocks mined (n)')
plt.ylabel('Time to mine n sequential blocks (minutes)')
plt.title('Empirical max-time data with linear & quadratic fits')
plt.legend()
plt.tight_layout()
plt.show()
