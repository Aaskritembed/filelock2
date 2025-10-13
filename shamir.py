import secrets
from typing import List
from constants import PRIME

# --------------------------
# Shamir Secret Sharing over prime field
# --------------------------
def _int_from_bytes(b: bytes) -> int:
    """Convert bytes to integer"""
    return int.from_bytes(b, byteorder='big')

def _int_to_bytes(i: int, length: int = None) -> bytes:
    """Convert integer to bytes with optional fixed length"""
    if length is None:
        length = (i.bit_length() + 7) // 8
    return i.to_bytes(length, byteorder='big')

def _eval_polynomial(coeffs: List[int], x: int, prime: int = PRIME) -> int:
    """Evaluate polynomial at x using Horner's method (more efficient)"""
    result = 0
    for coeff in reversed(coeffs):
        result = (result * x + coeff) % prime
    return result

def split_secret(secret_bytes: bytes, threshold: int, n: int) -> List[str]:
    """
    Split secret into n shares with threshold k using Shamir's Secret Sharing
    Returns list of share strings in format "x-yhex"
    """
    if threshold < 1:
        raise ValueError("Threshold must be at least 1")
    if threshold > n:
        raise ValueError("Threshold cannot exceed total shares")
    if n > 255:
        raise ValueError("Maximum 255 shares supported")
    
    secret_int = _int_from_bytes(secret_bytes)
    if secret_int >= PRIME:
        raise ValueError("Secret too large for chosen prime field")
    
    # Generate random polynomial coefficients
    coeffs = [secret_int] + [secrets.randbelow(PRIME) for _ in range(threshold - 1)]
    
    # Generate shares
    shares = []
    y_bytes_len = (PRIME.bit_length() + 7) // 8
    
    for i in range(1, n + 1):
        y = _eval_polynomial(coeffs, i)
        x_hex = format(i, 'x')
        y_hex = _int_to_bytes(y, y_bytes_len).hex()
        shares.append(f"{x_hex}-{y_hex}")
    
    return shares

def _mod_inverse(a: int, m: int) -> int:
    """Compute modular multiplicative inverse using extended Euclidean algorithm"""
    return pow(a, -1, m)

def _lagrange_interpolate(x: int, x_s: List[int], y_s: List[int], prime: int = PRIME) -> int:
    """Lagrange interpolation at point x"""
    if len(x_s) != len(y_s):
        raise ValueError("x_s and y_s must have same length")
    
    total = 0
    k = len(x_s)
    
    for i in range(k):
        xi, yi = x_s[i], y_s[i]
        numerator = 1
        denominator = 1
        
        for j in range(k):
            if i == j:
                continue
            xj = x_s[j]
            numerator = (numerator * (x - xj)) % prime
            denominator = (denominator * (xi - xj)) % prime
        
        inv_denominator = _mod_inverse(denominator, prime)
        lagrange_term = (yi * numerator % prime * inv_denominator) % prime
        total = (total + lagrange_term) % prime
    
    return total

def combine_shares(share_strs: List[str]) -> bytes:
    """Reconstruct secret from k shares"""
    if not share_strs:
        raise ValueError("No shares provided")
    
    x_s = []
    y_s = []
    
    for share in share_strs:
        if '-' not in share:
            raise ValueError("Invalid share format (missing '-' separator)")
        
        parts = share.split('-', 1)
        if len(parts) != 2:
            raise ValueError("Invalid share format")
        
        x_hex, y_hex = parts
        
        try:
            x = int(x_hex, 16)
            y = int.from_bytes(bytes.fromhex(y_hex), byteorder='big')
        except ValueError as e:
            raise ValueError(f"Invalid share encoding: {e}")
        
        if x in x_s:
            raise ValueError(f"Duplicate share x-coordinate: {x}")
        
        x_s.append(x)
        y_s.append(y)
    
    secret_int = _lagrange_interpolate(0, x_s, y_s)
    secret_bytes = _int_to_bytes(secret_int)
    
    # Pad to expected key size
    from constants import KEY_SIZE
    if len(secret_bytes) < KEY_SIZE:
        secret_bytes = b'\x00' * (KEY_SIZE - len(secret_bytes)) + secret_bytes
    
    return secret_bytes
