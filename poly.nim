import ntt, params, precomp, reduce
import private/chacha20
import private/sha3/shake128


type Poly* = object
  coeffs*: array[PARAM_N, uint16]


proc toLittleEndian16*(buf: openArray[byte]): uint16 =
  return uint16(buf[0]) or (uint16(buf[1]) shl 8)


proc toLittleEndian32*(buf: openArray[byte]): uint32 =
  result = uint32(buf[0])        or
           uint32(buf[1]) shl  8 or
           uint32(buf[2]) shl 16 or
           uint32(buf[3]) shl 24


proc polyFromBytes*(r: var Poly, a: openArray[byte]) =
  ## convert byte array `a` into polynomial `r`
  for i in 0 ..< PARAM_N div 4:
    # NOTE: each group of 7 bytes fills 4 coefficients in the polynomial
    r.coeffs[4*i+0] =  uint16(a[7*i+0])        or ((uint16(a[7*i+1]) and 0x3f) shl 8)
    r.coeffs[4*i+1] = (uint16(a[7*i+1]) shr 6) or  (uint16(a[7*i+2])           shl 2) or ((uint16(a[7*i+3]) and 0x0f) shl 10)
    r.coeffs[4*i+2] = (uint16(a[7*i+3]) shr 4) or  (uint16(a[7*i+4])           shl 4) or ((uint16(a[7*i+5]) and 0x03) shl 12)
    r.coeffs[4*i+3] = (uint16(a[7*i+5]) shr 2) or  (uint16(a[7*i+6])           shl 6)


proc polyToBytes*(p: Poly, r: var openArray[byte]) =
  ## convert polynomial `p` into byte array `r`
  for i in 0 ..< PARAM_N div 4:
    # NOTE: reduce polynomial coefficients using Barrett reduction
    var
      t0 = barrettReduce(p.coeffs[4*i + 0])
      t1 = barrettReduce(p.coeffs[4*i + 1])
      t2 = barrettReduce(p.coeffs[4*i + 2])
      t3 = barrettReduce(p.coeffs[4*i + 3])

     # NOTE: adjust coefficients to ensure they're within [0, PARAM_Q) range
    var
      m: int32
      c: int16

    # for t0
    m = int32(t0) - int32(PARAM_Q)
    c = int16(m shr 15)
    t0 = uint16(m xor (int32(t0) xor m) and int32(c))

    # for t1
    m = int32(t1) - int32(PARAM_Q)
    c = int16(m shr 15)
    t1 = uint16(m xor (int32(t1) xor m) and int32(c))

    # for t2
    m = int32(t2) - int32(PARAM_Q)
    c = int16(m shr 15)
    t2 = uint16(m xor (int32(t2) xor m) and int32(c))

    # for t3
    m = int32(t3) - int32(PARAM_Q)
    c = int16(m shr 15)
    t3 = uint16(m xor (int32(t3) xor m) and int32(c))

    # NOTE: pack coefficients into bytes efficiently
    r[7*i + 0] = byte(t0 and 0xFF)
    r[7*i + 1] = byte(t0 shr  8) or byte(t1 shl 6)
    r[7*i + 2] = byte(t1 shr  2)
    r[7*i + 3] = byte(t1 shr 10) or byte(t2 shl 4)
    r[7*i + 4] = byte(t2 shr  4)
    r[7*i + 5] = byte(t2 shr 12) or byte(t3 shl 2)
    r[7*i + 6] = byte(t3 shr  6)


proc polyUniform*(a: var Poly, seed: openArray[byte]) =
  ## sample polynomial coefficients uniformly using SHAKE128
  const nBlockRef = 16
  var
    nBlocks = nBlockRef
    pos: int
    ctr: int
    val: uint16
    ctx: Shake128Ctx
    buf: array[SHAKE128_RATE*nBlockRef, byte]
  
  ctx = newShake128Ctx()
  discard keccakAbsorb(ctx.state, seed)
  discard keccakSqueeze(ctx.state, buf, nBlockRef, ctx.padding)

  while ctr < PARAM_N: # populate polynomial until all coeffs are set
    val = (buf[pos] or (buf[pos+1] shl 8)) and 0x3fff'u16 # extract 14-bit value (pecialized for q = 12889)
    
    if val < PARAM_Q: # accept value if in valid range
      a.coeffs[ctr] = val
      inc ctr
    pos.inc(2)
    
    # NOTE: refill buffer if exhausted
    if pos > SHAKE128_RATE*nBlocks - 2:
      nBlocks = 1 # reduce block size for efficiency
      discard keccakSqueeze(ctx.state, buf, nBlocks, ctx.padding)
      pos = 0


proc polyGetNoise*(r: var Poly, seed: openArray[byte], nonce: byte) =
  ## generate noise polynomial `r` using ChaCha20 and a nonce
  const bufSize = 4*PARAM_N
  var
    buf: array[bufSize, byte]
    t, d, a, b: uint32
    n: array[8, byte]

  n[0] = nonce
  var ctx = newChaCha20Ctx(seed, n)
  ctx.encrypt(buf, buf)
  ctx.reset()

  for i in 0 ..< PARAM_N:
    t = toLittleEndian32(buf[i*4 ..< i*4+4])
    d = 0
    # NOTE: sum bits in positions 0, 8, 16, and 24 of `t`
    for j in 0 ..< 8:
      d += (t shr j) and 0x01010101
    # NOTE: calculate low and high parts of `d`
    a = ((d shr  8) and 0xff) +  (d         and 0xff)
    b =  (d shr 24)           + ((d shr 16) and 0xff)
    # NOTE: compute noise coefficient and adjust by PARAM_Q
    r.coeffs[i] = uint16(a) + PARAM_Q - uint16(b)
  buf.reset()


proc polyPointwise*(r: var Poly, a: Poly, b: Poly) =
  ## pointwise multiplication of polynomials `a` and `b`, result in `r`
  var t: uint16
  for i in 0 ..< PARAM_N:
    t = montgomeryReduce(3186 * uint32(b.coeffs[i])) # adjust `b` to Montgomery domain
    r.coeffs[i] = montgomeryReduce(uint32(a.coeffs[i]) * uint32(t)) # multiply and reduce


proc polyAdd*(r: var Poly, a: Poly, b: Poly) =
  ## add polynomials `a` and `b`, result in `r`
  for i in 0 ..< PARAM_N:
    r.coeffs[i] = barrettReduce(a.coeffs[i] + b.coeffs[i]) # sum and modular reduce


proc polyNtt*(r: var Poly) =
  ## apply NTT to polynomial `r` in place
  mulCoefficients(r.coeffs, psisBitrevMontgomery) # pre-process coefficients
  ntt(r.coeffs, omegasMontgomery) # NTT transformation


proc polyInvNtt*(r: var Poly) =
  ## apply inverse NTT to polynomial `r` in place
  bitrevVector(r.coeffs) # reverse bit order of indices
  ntt(r.coeffs, omegasInvMontgomery) # apply inverse NTT
  mulCoefficients(r.coeffs, psisInvMontgomery) # post-process coefficients
