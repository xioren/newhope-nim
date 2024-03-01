# NOTE: the degree of polynomials used in the scheme, typically a power of 2 for efficient NTT operations.
const PARAM_N* = 1024

# NOTE: security parameter defining the error distribution's width or other internal parameters.
const PARAM_K* = 16

# NOTE: the modulus for polynomial coefficients, chosen to support efficient arithmetic and NTT operations.
const PARAM_Q* = 12289 

# NOTE: the size in bytes of an encoded polynomial, calculated based on PARAM_N and the encoding scheme.
const POLY_BYTES* = 1792

# NOTE: the rate of the SHAKE128 hash function, determining how many bytes can be squeezed per round.
const SHAKE128_RATE* = 168

# NOTE: the size in bytes of the seed used for generating polynomials or keys, aligning with security requirements.
const NEWHOPE_SEEDBYTES* = 32

# NOTE: the size in bytes dedicated to storing reconciliation data in the key exchange process.
const NEWHOPE_RECBYTES* = 256

# NOTE: the size in bytes of Alice's message to Bob, including an encoded polynomial and a seed.
const NEWHOPE_SENDABYTES* = POLY_BYTES + NEWHOPE_SEEDBYTES

# NOTE: the size in bytes of Bob's message back to Alice, including an encoded polynomial and reconciliation data.
const NEWHOPE_SENDBBYTES* = POLY_BYTES + NEWHOPE_RECBYTES