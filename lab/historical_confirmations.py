"""
This script calculates the probability of mining a certain number of blocks in a certain amount of time.
Those times are collected from the block_analysis.py script which analyzes 800k blocks and determines the 
maximum time to mine a certain number of sequential blocks.
"""

from scipy.stats import gamma
from scipy.optimize import curve_fit
from block_analysis import get_associated_time_to_mines
import numpy as np
import matplotlib.pyplot as plt
"""
[CDF] Probability of 2 block/s mining in 139.23 minutes: 99.9986602030%
[CDF] Probability of 3 block/s mining in 163.68 minutes: 99.9988217247%
[CDF] Probability of 4 block/s mining in 233.87 minutes: 99.9999830624%
[CDF] Probability of 5 block/s mining in 284.42 minutes: 99.9999985981%
[CDF] Probability of 6 block/s mining in 312.12 minutes: 99.9999991867%
"""

# Parameters
scale = 10  # Scale (θ) = average time per block (minutes)
shape = 2 
max_times = 4*60

# CDF
probability = gamma.cdf(max_times, a=shape, scale=scale)
print(f"[CDF] Probability of {shape} block/s mining in {max_times:.2f} minutes: {probability*100:.10f}%")

# Parameters
scale = 10  # Scale (θ) = average time per block (minutes)
search_ranges = range(2, 100)
shape = list(search_ranges) # Shape (k) = num blocks 
max_times = [max_time / 60 for block_range, max_time in get_associated_time_to_mines(windows=search_ranges)[0].items()]

# CDF
probabilities = []
for i in range(len(shape)):
    probability = gamma.cdf(max_times[i], a=shape[i], scale=scale)
    probabilities.append(probability)
    print(f"[CDF] Probability of {shape[i]} block/s mining in {max_times[i]:.2f} minutes: {probability*100:.10f}%")

blocks = np.array(shape, dtype=float)
minutes = np.array(max_times, dtype=float)

# Helper for R²
def r2(actual, predicted):
    ss_res = np.sum((actual - predicted)**2)
    ss_tot = np.sum((actual - actual.mean())**2)
    return 1 - ss_res/ss_tot

# Linear fit
lin_coef = np.polyfit(blocks, minutes, 1)
lin_pred = np.poly1d(lin_coef)(blocks)
r2_lin = r2(minutes, lin_pred)

# Quadratic fit
quad_coef = np.polyfit(blocks, minutes, 2)
quad_pred = np.poly1d(quad_coef)(blocks)
r2_quad = r2(minutes, quad_pred)

# Power-law non-linear fit
def power_law(n, c, d):
    return c * n**d

# Square root fit
def sqrt_law(n, a, b):
    return a * np.sqrt(n) + b

p0 = (minutes[0], 0.7)  # crude initial guess
pwr_coef, _ = curve_fit(power_law, blocks, minutes, p0=p0, maxfev=10000)
c_hat, d_hat = pwr_coef
pwr_pred = power_law(blocks, c_hat, d_hat)
r2_pwr = r2(minutes, pwr_pred)

# Square root fit
sqrt_p0 = (10.0, 0.0)  # initial guess for sqrt fit
sqrt_coef, _ = curve_fit(sqrt_law, blocks, minutes, p0=sqrt_p0, maxfev=10000)
a_hat, b_hat = sqrt_coef
sqrt_pred = sqrt_law(blocks, a_hat, b_hat)
r2_sqrt = r2(minutes, sqrt_pred)

# Print formulas
print("Linear    : t(n) ≈ {:.4f}·n + {:.2f}          R²={:.4f}".format(lin_coef[0], lin_coef[1], r2_lin))
print("Quadratic : t(n) ≈ {:.6f}·n² + {:.4f}·n + {:.2f}  R²={:.4f}".format(
    quad_coef[0], quad_coef[1], quad_coef[2], r2_quad))
print("Power‑law : t(n) ≈ {:.2f}·n^{:.3f}              R²={:.4f}".format(c_hat, d_hat, r2_pwr))
print("Square root : t(n) ≈ {:.2f}·√n + {:.2f}          R²={:.4f}".format(a_hat, b_hat, r2_sqrt))

# Plot
plt.figure(figsize=(8,5))
plt.scatter(blocks, minutes, color='tab:orange', label='data', s=18)
plt.plot(blocks, lin_pred, label=f'linear (R²≈{r2_lin:.3f})')
plt.plot(blocks, quad_pred, label=f'quadratic (R²≈{r2_quad:.3f})')
plt.plot(blocks, pwr_pred, label=f'power‑law (R²≈{r2_pwr:.3f})', linestyle='--')
plt.plot(blocks, sqrt_pred, label=f'square root (R²≈{r2_sqrt:.3f})', linestyle=':')
plt.xlabel('Blocks')
plt.ylabel('Minutes')
plt.title('Sequential‑block mining times: linear vs quadratic vs power‑law vs square root')
plt.legend()
plt.tight_layout()
plt.show()