# utils/gaussian.py

import random
import math
from utils.params import GAUSSIAN_STDDEV

def constant_time_gaussian(mu=0, sigma=GAUSSIAN_STDDEV):
    # Box-Muller transform (constant-ish time)
    while True:
        u1 = random.random()
        u2 = random.random()
        z0 = math.sqrt(-2.0 * math.log(u1)) * math.cos(2 * math.pi * u2)
        val = round(mu + sigma * z0)
        if abs(val) <= 6 * sigma:
            return val
