## Procedure

We denote `x = value`  and `m = modulus` here.

The algorithm will output `r = x mod m` with the below procedures:

1. `q₁ ← x`, `q₂ ← q₁ * ratio`, `q₃ ← ⌊q₂/b²⌋`.
2. `r₁ ← x mod b²`, `r₂ ← q₃ * m mod b²`, `r ← r₁ - r₂`.
3. If `r ≥ m` do: `r ← r - m`.
4. Return(`r`).

## Proof:

∵ `q₁ = x` , `⌊b² / m⌋ - 1 < ratio ≤ ⌊b² / m⌋`

∴ `⌊x * b² / m⌋ - x < q₂ = q₁ * ratio ≤ ⌊x * b² / m⌋`
    
∴ `⌊x / m⌋ - 2 < q₃ = ⌊q₂ / b²⌋ ≤ ⌊x / m⌋`
    
∴ `⌊x / m⌋ - 1 ≤ q₃ ≤ ⌊x / m⌋`
    
∴ `x - q₃ * m mod b² < 2 * m`
