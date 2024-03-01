import params, poly
import private/chacha20


proc abs(v: int32): int32 =
  # NOTE: create a mask to determine the sign of `v`
  let mask = v shr 31
  # NOTE: use XOR to negate `v` if negative, then subtract mask to adjust for sign
  return (v xor mask) - mask


proc f(v0, v1: var int32, x: int32): int32 =
  var xit, t, r, b: int32
  
  # NOTE: approximate division by PARAM_Q using multiplication and shift
  b = x * 2730
  t = b shr 25
  # NOTE: correct the approximation
  b = x - (t * PARAM_Q)
  # NOTE: adjust `t` based on the sign
  b = (PARAM_Q - 1) - b
  b = b shr 31 # create mask for adjustment
  t -= b # final adjustment of `t`
  
  # NOTE: calculate v0
  r = t and 1 # get LSB for rounding
  xit = t shr 1 # fivide by 2
  v0 = xit + r  # adjust `v0` for rounding
  
  # NOTE: calculate v1
  dec t
  r = t and 1 # get LSB for rounding
  v1 = (t shr 1) + r # adjust `v1` for rounding
  
  # NOTE: absolute difference adjusted by the factor of 2*PARAM_Q
  return abs(x - (v0 * 2 * PARAM_Q))


proc g(x: int32): int32 =
  var t, c, b: int32

  # NOTE: approximate division by 4*PARAM_Q using multiplication and shift
  b = x * 2730
  t = b shr 27
  # NOTE: correct the approximation
  b = x - t * (PARAM_Q*4)
  # NOTE: adjust `t` based on the sign
  b = (PARAM_Q*4) - b
  b = b shr 31 # create mask for adjustment
  t -= b # final adjustment of `t`
  
  # NOTE: round `t` to nearest integer
  c = t and 1 # get LSB for rounding
  t = (t shr 1) + c  # compute rounded `t`
  
  # NOTE: rescale `t` back to original scale
  t *= 8 * PARAM_Q

  return abs(t - x)


proc LDDecode(xi0, xi1, xi2, xi3: int32): int16 =
  var t = g(xi0) + g(xi1) + g(xi2) + g(xi3)
  
  # NOTE: normalize and adjust the sum
  t -= 8 * PARAM_Q
  # NOTE: convert t to a sign mask
  t = t shr 31
  # NOTE: return LSB of t as a binary decision
  return int16(t and 1)


proc helpRec*(c: var Poly, v: Poly, seed: openArray[byte], nonce: byte) =
  var
    v0, v1, v_tmp: array[4, int32]
    k: int32
    rbit: int32
    rand: array[32, byte]
    n: array[8, byte]
  
  n[7] = nonce
  var ctx = newChaCha20Ctx(seed, n)
  ctx.encrypt(rand, rand)

  for i in 0 ..< 256:
    rbit = int32((rand[i shr 3] shr (i and 7)) and 1) # extract random bit for index i
    
    # NOTE: calculate k using function f and adjustments with rbit
    k  = f(v0[0], v1[0], 8 * int32(v.coeffs[  0 + i]) + 4 * rbit)
    k += f(v0[1], v1[1], 8 * int32(v.coeffs[256 + i]) + 4 * rbit)
    k += f(v0[2], v1[2], 8 * int32(v.coeffs[512 + i]) + 4 * rbit)
    k += f(v0[3], v1[3], 8 * int32(v.coeffs[768 + i]) + 4 * rbit)

    k = (2 * PARAM_Q - 1 - k) shr 31
    
    # NOTE: compute new coefficients based on k
    for j in 0 ..< 4:
      v_tmp[j] = ((not k) and v0[j]) xor (k and v1[j])
    
    # NOTE: assign new coefficients to c based on v_tmp and k
    c.coeffs[  0 + i] = uint16((v_tmp[0] -    v_tmp[3]) and 3)
    c.coeffs[256 + i] = uint16((v_tmp[1] -    v_tmp[3]) and 3)
    c.coeffs[512 + i] = uint16((v_tmp[2] -    v_tmp[3]) and 3)
    c.coeffs[768 + i] = uint16((   -k    +  2*v_tmp[3]) and 3)


proc rec*(key: var openArray[byte], v: Poly, c: Poly) =
  ## calculate key bits from polynomial coefficients
  var tmp: array[4, int32]
  
  # NOTE: compute tmp values as part of reconciliation process
  for i in 0 ..< 256:
    tmp[0] = 16 * int32(PARAM_Q) + 8 * int32(v.coeffs[  0 + i]) - int32(PARAM_Q) * (2 * int32(c.coeffs[  0 + i]) + int32(c.coeffs[768 + i]))
    tmp[1] = 16 * int32(PARAM_Q) + 8 * int32(v.coeffs[256 + i]) - int32(PARAM_Q) * (2 * int32(c.coeffs[256 + i]) + int32(c.coeffs[768 + i]))
    tmp[2] = 16 * int32(PARAM_Q) + 8 * int32(v.coeffs[512 + i]) - int32(PARAM_Q) * (2 * int32(c.coeffs[512 + i]) + int32(c.coeffs[768 + i]))
    tmp[3] = 16 * int32(PARAM_Q) + 8 * int32(v.coeffs[768 + i]) - int32(PARAM_Q) *                                 int32(c.coeffs[768 + i])
    
    # NOTE: use LDDecode to determine key bit, then OR it into the key at the appropriate bit position
    key[i shr 3] = key[i shr 3] or byte(LDDecode(tmp[0], tmp[1], tmp[2], tmp[3]) shl (i and 7))
  tmp.reset()