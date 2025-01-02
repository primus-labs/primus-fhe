This module implements some functions and methods for modular arithmetic based on **barrett reduction**.

Barrett reduction computes `r ≡ x mod m` given `x` and `m` and return `r` where `r < m`.

First, we need decide the radix `b`, which is chosen to be close to the word-size of the processor. Here, `b` = 2^64.

The algorithm then precomputes a quantity ratio `µ = ⌊b^(2k)/m⌋`, where `k` is the length of `m` based on radix `b`.

For example, we denote `x` = (x_(2k-1) ... x₁ x₀) and `m` = (m_(k-1) ... m₁ m₀) (m_(k-1) ≠ 0) based on radix `b`.

Then, the algorithm will output `r ≡ x mod m` with the below procedures:

1. `q₁ ← ⌊x/b^(k-1)⌋`, `q₂ ← q₁ · µ`, `q₃ ← ⌊q₂/b^(k+1)⌋`.
2. `r₁ ← x mod b^(k+1)`, `r₂ ← (q₃ · m) mod b^(k+1)`, `r ← r₁ - r₂`.
3. If `r ≥ m` do: `r ← r - m`.
4. Return(`r`).