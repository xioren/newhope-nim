import ntt, params, poly, precomp, reduce
import private/chacha20
import private/sha3/shake128

export poly

# NOTE: additional polynomial functions from NewHope-Simple

proc coeffFreeze(x: uint16): uint16 =
  let r = barrettReduce(x)
  # NOTE: use int32 to prevent overflow and keep sign
  let m = int32(r) - int32(PARAM_Q)
  # NOTE: right shift, preserving sign extension
  let c = int16(m) shr 15
  # NOTE: perform bitwise operations, converting c back to uint16 to match types
  return uint16(m) xor ((uint16(r) xor uint16(m)) and uint16(c))


proc flipAbs(x: uint16): uint16 =
  # NOTE: use int32 for proper arithmetic
  let r = int32(coeffFreeze(x)) - int32(PARAM_Q div 2)
  # NOTE: right shift for sign extension mask
  let m = r shr 15
  # NOTE: apply bitwise operation for abs, converting back to uint16
  return uint16((r + m) xor m)


proc compress*(p: Poly, r: var openArray[byte], idx: int) =
  ## compress polynomial `p` coefficients and store in byte array `r` at position `idx`
  var t: array[8, uint32]

  var i, k: int # `i` for polynomial index, `k` for byte array index
  while i < PARAM_N: # iterate over all coefficients of polynomial `p`
    for j in 0 ..< t.len: # process 8 coefficients at a time
      t[j] = uint32(coeffFreeze(p.coeffs[i+j])) # normalize coefficient
      t[j] = ((t[j] shl 3) + PARAM_Q div 2) div PARAM_Q and 0x7 # compress
    
    # NotE: pack 8 compressed coefficients into 3 bytes
    r[idx+k  ] = byte(t[0])       or byte(t[1] shl 3) or byte(t[2] shl 6)
    r[idx+k+1] = byte(t[2] shr 2) or byte(t[3] shl 1) or byte(t[4] shl 4) or byte(t[5] shl 7)
    r[idx+k+2] = byte(t[5] shr 1) or byte(t[6] shl 2) or byte(t[7] shl 5)
    i += 8 # move to the next set of 8 coefficients
    k += 3 # move to the next set of 3 bytes in `r`

  t.reset()


proc decompress*(p: var Poly, a: openArray[byte], idx: int) =
  ## decompresses bytes starting at `idx` in array `a` into polynomial `p`
  var i = 0 # iterator for polynomial coefficients
  var aa = a[idx ..< a.len] # slice of input array from `idx`
  var a0, a1, a2: uint16
  
  while i < PARAM_N:
    # NOTE: unpack 3 bytes back into 8 coefficients
    a0 = uint16(aa[0])
    a1 = uint16(aa[1])
    a2 = uint16(aa[2])
    p.coeffs[i+0] =  a0                       and 7
    p.coeffs[i+1] = (a0 shr 3)                and 7
    p.coeffs[i+2] = (a0 shr 6) or ((a1 shl 2) and 4)
    p.coeffs[i+3] = (a1 shr 1)                and 7
    p.coeffs[i+4] = (a1 shr 4)                and 7
    p.coeffs[i+5] = (a1 shr 7) or ((a2 shl 1) and 6)
    p.coeffs[i+6] = (a2 shr 2)                and 7
    p.coeffs[i+7] = (a2 shr 5)
    
    # NOTE: rescale coefficients back to their original range
    for j in 0 ..< 8:
      p.coeffs[i+j] = uint16((uint32(p.coeffs[i+j])*PARAM_Q + 4) shr 3)
    i += 8
    aa = aa[3 ..< aa.len]


proc fromMsg*(p: var Poly, msg: openArray[byte]) =
  ## convert a 256-bit message into a polynomial representation
  for i in 0 ..< 32: # iterate over each byte in `msg`
    for j in 0 ..< 8: # iterate over each bit in the current byte
      let bit = (msg[i] shr j) and 1'u8 # extract the bit
      let mask = if bit == 1'u8: 0xFFFF'u16 else: 0'u16 # create a mask based on the bit

      # NOTE: apply the mask to set coefficients, spreading the bit's influence
      p.coeffs[8*i + j      ] = mask and (PARAM_Q div 2)
      p.coeffs[8*i + j + 256] = mask and (PARAM_Q div 2)
      p.coeffs[8*i + j + 512] = mask and (PARAM_Q div 2)
      p.coeffs[8*i + j + 768] = mask and (PARAM_Q div 2)


proc toMsg*(p: Poly, msg: var openArray[byte]) =
  ## extract a 256-bit message from a polynomial representation
  var t: uint16
  for i in 0 ..< 256: # iterate over quarter segments of `p`
    # NOTE: sum absolute values of corresponding coefficients in each segment
    t  = flipAbs(p.coeffs[i+  0])
    t += flipAbs(p.coeffs[i+256])
    t += flipAbs(p.coeffs[i+512])
    t += flipAbs(p.coeffs[i+768])

    t = (t - PARAM_Q) # adjust total sum by subtracting PARAM_Q
    t = t shr 15 # normalize to get the bit value
    msg[i shr 3] = msg[i shr 3] or byte(t shl (i and 7)) # set the bit in the message


proc sub*(p: var Poly, a, b: Poly) =
  ## subtract polynomial `b` from `a`, storing result in `p`
  for i in 0 ..< p.coeffs.len: # iterate over all coefficients
    # NOTE: use Barrett reduction to efficiently compute modular subtraction
    p.coeffs[i] = barrettReduce(a.coeffs[i] + 3*PARAM_Q - b.coeffs[i])