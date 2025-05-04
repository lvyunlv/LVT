import numpy as np
import pandas as pd

# Define the function mappings and their domains
functions = {
    "log": {"func": np.log, "domain": (1e-3, 64), "steps": 2**8},          # Avoid log(0)
    "reciprocal": {"func": lambda x: 1 / x, "domain": (1, 64), "steps": 2**7},
    "sqrt": {"func": np.sqrt, "domain": (0, 256), "steps": 2**6},
    "invsqrt": {"func": lambda x: 1 / np.sqrt(x), "domain": (1e-3, 256), "steps": 2**6},
    "sin": {"func": np.sin, "domain": (-64, 64), "steps": 2**5},
    "cos": {"func": np.cos, "domain": (-64, 64), "steps": 2**5},
    "sigmoid": {"func": lambda x: 1 / (1 + np.exp(-x)), "domain": (-64, 64), "steps": 2**6},
    "tanh": {"func": np.tanh, "domain": (-64, 64), "steps": 2**5},
    "erf": {"func": lambda x: np.math.erf(x), "domain": (-64, 64), "steps": 2**3},
    "gelu": {"func": lambda x: 0.5 * x * (1 + np.tanh(np.sqrt(2 / np.pi) * (x + 0.044715 * x**3))),
             "domain": (-64, 64), "steps": 2**4},
    "silu": {"func": lambda x: x / (1 + np.exp(-x)), "domain": (-64, 64), "steps": 2**6},
}

# Generate lookup tables
lookup_tables = {}
for name, info in functions.items():
    x_vals = np.linspace(info["domain"][0], info["domain"][1], info["steps"], dtype=np.float64)
    try:
        y_vals = np.array([info["func"](x) for x in x_vals], dtype=np.float64)
    except Exception as e:
        y_vals = np.full_like(x_vals, np.nan)
        print(f"Error processing function {name}: {e}")
    lookup_tables[name] = pd.DataFrame({"x": x_vals, "y": y_vals})

lookup_tables.keys()  # Show which tables are generated

