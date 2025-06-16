import random
import secrets
import numpy as np
from collections import Counter
import math
import importlib.util

def shannon_entropy(data):
    """
    Calculates the Shannon entropy of a given byte sequence.
    Max entropy for a byte (0-255) is 8.0 bits.
    """
    if not data:
        return 0.0
    counter = Counter(data)
    total = len(data)
    entropy = -sum((count / total) * math.log2(count / total)
                   for count in counter.values())
    return entropy

def bit_level_entropy(data):
    """
    Calculates the bit-level entropy of a byte sequence.
    Treats the data as a stream of bits (0s and 1s).
    Max entropy for a bit is 1.0 bit.
    """
    if not data:
        return 0.0
    bits = ''.join(f"{byte:08b}" for byte in data) # Convert each byte to an 8-bit binary string
    total = len(bits)
    ones = bits.count('1')
    zeros = bits.count('0')
    p1 = ones / total if total else 0
    p0 = zeros / total if total else 0
    entropy = 0
    if p1 > 0:
        entropy -= p1 * math.log2(p1)
    if p0 > 0:
        entropy -= p0 * math.log2(p0)
    return entropy

def generate_samples(generator_type, size):
    """
    Generates a list of random bytes (integers from 0 to 255)
    using different random number generators.
    """
    if generator_type == "random":
        return [random.randint(0, 255) for _ in range(size)]
    elif generator_type == "secrets":
        # secrets module is cryptographically strong
        return [secrets.randbelow(256) for _ in range(size)]
    elif generator_type == "numpy":
        # numpy.random for numerical tasks, generally fast
        # Check if numpy is installed, otherwise raise an error
        if not hasattr(np, 'random'):
            raise ImportError("numpy is required for 'numpy' generator type.")
        return list(np.random.randint(0, 256, size))
    elif generator_type == "custom" and hasattr(generate_samples, "custom_func"):
        # For custom RNG loaded dynamically (not supported in web app directly, but kept for completeness)
        return generate_samples.custom_func(size)
    else:
        raise ValueError(f"Unknown generator type: {generator_type}")

# Note on `custom_func`:
# The `load_custom_rng` functionality from your original Tkinter app,
# which uses `importlib.util` and assigns to `generate_samples.custom_func`,
# is generally not suitable for a web application due to security implications
# and the stateless nature of web requests. It's best to omit dynamic loading
# of arbitrary Python files in a public-facing web app.
# For internal use or if you fully understand the risks, this part of the
# `generate_samples` function remains, but its activation via web UI is removed.