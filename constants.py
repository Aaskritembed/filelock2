# --------------------------
# Constants
# --------------------------
PRIME = 2**521 - 1  # Mersenne prime for Shamir's Secret Sharing
KEY_SIZE = 32  # AES-256
NONCE_SIZE = 12  # GCM recommended nonce size
PBKDF2_ITERATIONS = 600000  # OWASP recommendation for 2023+
