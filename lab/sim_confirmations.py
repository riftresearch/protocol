"""
erlang_fit.py
--------------
Compute the confidence-quantile confirmation time for 1…N Bitcoin blocks (modelled
as an Erlang/Gamma process), fit a square-root + linear model
    t(k) = β0 + β1*sqrt(k) + β2*k
by ordinary least squares, print per-k errors and overall RMSE,
and display a plot comparing the fitted curve with the exact quantiles.
"""

import numpy as np
import matplotlib.pyplot as plt
from scipy.stats import gamma
from typing import Tuple, Dict, Any


def fit_confirmation_model(
    confidence: float = 0.999,
    end_block: int = 255,
    scale: float = 10.0,
    heavy_k: int = 6,
    epsilon: float = 1e-4,
    show_plot: bool = True,
    print_results: bool = True
) -> Dict[str, Any]:
    """
    Fit a confirmation time model t(k) = β0 + β1*sqrt(k) + β2*k to Bitcoin block confirmation times.
    
    Args:
        confidence: Probability quantile (e.g., 0.99 for 99th percentile)
        end_block: Maximum number of blocks to model
        scale: Average block interval in minutes (default 10.0)
        heavy_k: Number of initial blocks to weight heavily in fitting
        epsilon: Weight for blocks beyond heavy_k (tail weight)
        show_plot: Whether to display the fitted curve plot
        print_results: Whether to print detailed results
        
    Returns:
        Dictionary containing:
            - coefficients: (β0, β1, β2) tuple
            - k_vals: Array of block numbers
            - t_exact: Exact quantile times from Gamma distribution
            - t_fit: Fitted model predictions
            - errors_abs: Absolute errors
            - errors_rel: Relative errors
            - rmse: Root mean square error
            - weights: Weights used in fitting
    """
    
    # --------------------------------------------------------
    # Exact quantile times from the Gamma (Erlang) Inverse CDF
    # --------------------------------------------------------
    k_vals = np.arange(1, end_block + 1)
    t_exact = gamma.ppf(confidence, a=k_vals, scale=scale)

    # --------------------------------------------------------
    # Weighted fit:  t(k) = β0 + β1*sqrt(k) + β2*k
    #                weights w_k = two constant values (focus on small k)
    # --------------------------------------------------------
    X = np.column_stack([np.ones_like(k_vals), np.sqrt(k_vals), k_vals])
    weights = np.where(k_vals <= heavy_k, 1.0, epsilon)
    W = np.diag(weights)

    beta = np.linalg.solve(X.T @ W @ X, X.T @ W @ t_exact)
    β0, β1, β2 = beta

    t_fit = X @ beta
    errors_abs = np.abs(t_fit - t_exact)
    errors_rel = errors_abs / t_exact
    rmse = np.sqrt(np.average((t_fit - t_exact)**2, weights=weights))

    # --------------------------------------------------------
    # Print results if requested
    # --------------------------------------------------------
    if print_results:
        print(f"\nConfidence level: {confidence}")
        print(f"End block: {end_block}")
        print(f"Heavy weighting up to k={heavy_k}, tail weight={epsilon}")
        print("\nPer-k error (minutes):")
        print(" k   exact     fitted    abs_err   rel_err")
        print("-----------------------------------------------")
        for k, te, tf, ae, re in zip(k_vals, t_exact, t_fit, errors_abs, errors_rel):
            print(f"{k:2d}  {te:8.2f}  {tf:8.2f}  {ae:8.4f}  {re:8.5f}")

        print("\nCoefficients:")
        print(f"  β0 = {β0:.6f}") 
        print(f"  β1 = {β1:.6f}")
        print(f"  β2 = {β2:.6f}")
        print(f"RMSE = {rmse:.6f} minutes  ({rmse/np.mean(t_exact)*100:.5f}% of mean)")

    # --------------------------------------------------------
    # Plot if requested
    # --------------------------------------------------------
    if show_plot:
        k_plot = np.linspace(0, end_block, 400)
        t_plot = β0 + β1 * np.sqrt(k_plot) + β2 * k_plot

        plt.figure(figsize=(9, 6))
        plt.scatter(k_vals, t_exact, color="tab:blue", 
                   label=f"Gamma {confidence:.4f}-quantile")
        plt.plot(k_plot, t_plot, color="tab:red",
                 label=f"Fit: t = {β0:.2f}+{β1:.2f}√k+{β2:.2f}k")
        plt.title(f"Confirmation-time upper bound vs number of blocks (p = {confidence})")
        plt.xlabel("Number of blocks  k")
        plt.ylabel("Time (minutes)")
        plt.grid(True, ls=":", alpha=0.7)
        plt.legend()
        plt.tight_layout()
        plt.show()

    return {
        'coefficients': (β0, β1, β2),
        'k_vals': k_vals,
        't_exact': t_exact,
        't_fit': t_fit,
        'errors_abs': errors_abs,
        'errors_rel': errors_rel,
        'rmse': rmse,
        'weights': weights
    }


def predict_confirmation_time(k: int, coefficients: Tuple[float, float, float]) -> float:
    """
    Predict confirmation time for k blocks using fitted coefficients.
    
    Args:
        k: Number of blocks
        coefficients: (β0, β1, β2) tuple from fit_confirmation_model
        
    Returns:
        Predicted confirmation time in minutes
    """
    β0, β1, β2 = coefficients
    return β0 + β1 * np.sqrt(k) + β2 * k


def main():
    """Compute model params for confirmation model fitting."""
    confidences = [
        0.999999999,
    ]

    for confidence in confidences:
        print(f"=== Confidence Model ({confidence*100}%) ===")
        result = fit_confirmation_model(
            confidence=confidence,
            end_block=255,
            heavy_k=6,
            epsilon=1e-4,
            show_plot=False,
            print_results=True
        )
        β0, β1, β2 = result['coefficients']
        print(f"Equation: t(k) = {β0:.6f} + {β1:.6f}√k + {β2:.6f}k")
        print("\nFirst 6 confirmations and errors:")
        print("k\tExact (min)\tFit (min)\tAbs Error\tRel Error")
        for i in range(6):
            k = result['k_vals'][i]
            exact = result['t_exact'][i]
            fit = result['t_fit'][i]
            abs_err = result['errors_abs'][i]
            rel_err = result['errors_rel'][i]
            print(f"{k}\t{exact:.6f}\t{fit:.6f}\t{abs_err:.6f}\t{rel_err:.6f}")
        print()


if __name__ == "__main__":
    main()
