import std/[strutils, sysrand]
import error_correction, params, poly
import private/sha3/sha3_256

#[
  NewHope is a key-exchange protocol based on the Ring-Learning-with-Errors (Ring-LWE) problem
  https://cryptojedi.org/papers/newhope-20160328.pdf
  based on https://github.com/tpoeppelmann/newhope and https://github.com/Yawning/newhope
]#

type
  PrivateKeyAlice = object
    sk: Poly
  PublicKeyAlice = object
    send: array[NEWHOPE_SENDABYTES, byte]
  PublicKeyBob = object
    send: array[NEWHOPE_SENDBBYTES, byte]

const SharedSecretSize = 32

############################################################################################

proc hex*(digest: openArray[byte]): string =
  ## produces a hex string of length digest * 2
  result = newStringOfCap(digest.len + digest.len)
  for b in digest:
    result.add(b.toHex(2).toLowerAscii())

  return result


proc memWipe[T](obj: var openArray[T]) =
  for idx in 0 ..< obj.len:
    obj[idx] = default(T)

############################################################################################

proc encodeA(r: var openArray[byte], pk: Poly, seed: openArray[byte]) =
  ## encode public key `pk` and `seed` into byte array `r`
  pk.polyToBytes(r) # convert polynomial `pk` to bytes and store in `r`
  for i in 0 ..< NEWHOPE_SEEDBYTES: # copy `seed` bytes to `r`, following `pk` bytes
    r[POLY_BYTES + i] = seed[i]


proc decodeA(pk: var Poly, seed: var openArray[byte], r: openArray[byte]) =
  ## decode public key `pk` and `seed` from byte array `r`
  pk.polyFromBytes(r) # convert bytes from `r` into polynomial `pk`
  for i in 0 ..< seed.len: # extract `seed` bytes from `r`, following `pk` bytes
    seed[i] = r[POLY_BYTES + i]


proc encodeB(r: var openArray[byte], b: Poly, c: Poly) =
  ## encode polynomials `b` and `c` into byte array `r`
  b.polyToBytes(r) # convert polynomial `b` to bytes and store in `r`
  for i in 0 ..< PARAM_N div 4: # pack `c` coefficients into bytes, 4 coefficients per byte
    r[POLY_BYTES + i] = byte(c.coeffs[4*i + 0]      ) or
                        byte(c.coeffs[4*i + 1] shl 2) or
                        byte(c.coeffs[4*i + 2] shl 4) or
                        byte(c.coeffs[4*i + 3] shl 6)


proc decodeB(b: var Poly, c: var Poly, r: openArray[byte]) =
  ## decode polynomials `b` and `c` from byte array `r`
  b.polyFromBytes(r) # convert bytes from `r` into polynomial `b`
  for i in 0 ..< PARAM_N div 4: # unpack bytes into `c` coefficients, 4 coefficients per byte
    c.coeffs[4*i + 0] = uint16(r[POLY_BYTES + i]      ) and 0x03
    c.coeffs[4*i + 1] = uint16(r[POLY_BYTES + i] shr 2) and 0x03
    c.coeffs[4*i + 2] = uint16(r[POLY_BYTES + i] shr 4) and 0x03
    c.coeffs[4*i + 3] = uint16(r[POLY_BYTES + i] shr 6)


proc newPublicKeyAlice*(msg: openArray[byte]): PublicKeyAlice =
  if msg.len != NEWHOPE_SENDABYTES:
    raise newException(ValueError, "cannot create key from message of length $1" % $msg.len)
  for i, b in msg:
    result.send[i] = b


proc newPublicKeyBob*(msg: openArray[byte]): PublicKeyBob =
  if msg.len != NEWHOPE_SENDBBYTES:
    raise newException(ValueError, "cannot create key from message of length $1" % $msg.len)
  for i, b in msg:
    result.send[i] = b


proc newPublicKeyAlice*(msg: string): PublicKeyAlice =
  return newPublicKeyAlice(msg.toOpenArrayByte(0, msg.len.pred))


proc newPublicKeyBob*(msg: string): PublicKeyBob =
  return newPublicKeyBob(msg.toOpenArrayByte(0, msg.len.pred))
  
############################################################################################

proc generateKeyPairAlice*(): tuple[privKey: PrivateKeyAlice, pubKey: PublicKeyAlice] =
  ## generate a key pair for Alice and encode public key for transmission to Bob
  var
    a, e, r, pk: Poly # polynomials for key generation
    seed, noiseSeed: array[NEWHOPE_SEEDBYTES, byte] # seeds for randomness
    privKey: PrivateKeyAlice
    pubKey: PublicKeyAlice

  discard urandom(seed)
  # NOTE: hash seed for additional security
  var ctx = newSha3_256Ctx(seed)
  seed = ctx.digest()
  a.polyUniform(seed) # create polynomial `a` uniformly from seed
  
  # NOTE: generate noise polynomials for private key and error term
  discard urandom(noiseSeed)
  privKey.sk.polyGetNoise(noiseSeed, 0) # noise for private key
  privKey.sk.polyNtt() # convert private key to NTT domain

  e.polyGetNoise(noiseSeed, 1) # noise for error term
  e.polyNtt() # convert error term to NTT domain
  
  # NOTE: compute public key: pk = a*s + e
  r.polyPointwise(privKey.sk, a)
  pk.polyAdd(e, r) # add error term to get pk
  
  # NOTE: encode public key and seed for transmission
  pubKey.send.encodeA(pk, seed)
  
  noiseSeed.reset()
  return (privKey, pubKey)


proc keyExchangeBob*(alicePubKey: PublicKeyAlice): tuple[pubKey: PublicKeyBob, sharedSec: array[SharedSecretSize, byte]] =
  ## Bob generates his public key and a shared secret key using Alice's public key
  var
    pka, a, sp, ep, u, v, epp, r: Poly # polynomials for key exchange
    seed, noiseSeed: array[NEWHOPE_SEEDBYTES, byte] # seeds for generating polynomials
    pubKey: PublicKeyBob
    sharedSec: array[SharedSecretSize, byte]

  discard urandom(noiseSeed)

  pka.decodeA(seed, alicePubKey.send) # decode Alice's public key and seed
  a.polyUniform(seed) # generate uniform polynomial `a` from seed
  
  # NOTE: generate noise polynomials for Bob's private key, error terms
  sp.polyGetNoise(noiseSeed, 0) # noise for Bob's private key
  sp.polyNtt() # convert to NTT domain
  ep.polyGetNoise(noiseSeed, 1) # noise for first error term
  ep.polyNtt() # convert to NTT domain
  epp.polyGetNoise(noiseSeed, 2) # noise for second error term
  
  # NOTE: compute u and v for Bob's public key and shared secret
  u.polyPointwise(a, sp) # u = a*s' + e'
  u.polyAdd(u, ep) # add error term `ep` to `u`

  v.polyPointwise(pka, sp) # v = pka*s' (in NTT domain)
  v.polyInvNtt() # convert `v` back from NTT domain
  v.polyAdd(v, epp) # add error term `epp` to `v`
  
  # NOTE: compute reconciliation polynomial `r`
  r.helpRec(v, noiseSeed, 3)
  
  # NOTE: encode Bob's public key `u` and reconciliation polynomial `r` for transmission
  pubKey.send.encodeB(u, r)
  # NOTE: # compute shared secret based on `v` and `r`
  sharedSec.rec(v, r)

  # NOTE: hash the shared secret to finalize
  var ctx = newSha3_256Ctx(sharedSec)
  
  noiseSeed.reset()
  sharedSec.reset()
  sp.reset()
  v.reset()

  return (pubKey, ctx.digest())


proc keyExchangeAlice*(bobPubKey: PublicKeyBob, alicePrivKey: PrivateKeyAlice): array[SharedSecretSize, byte] =
  ## Alice generates the shared secret key using Bob's public key
  var
    u, r, vp: Poly # polynomials for decoding Bob's public key and computing shared secret
    sharedSec: array[SharedSecretSize, byte]

  u.decodeB(r, bobPubKey.send) # decode Bob's public key `u` and reconciliation polynomial `r`
  
  # NOTE: compute v' = u * s (in NTT domain)
  vp.polyPointwise(alicePrivKey.sk, u)
  vp.polyInvNtt() # convert `vp` back from NTT domain
  
  # NOTE: sharedSec <- Rec(v', r)
  sharedSec.rec(vp, r)
  
  # NOTE: hash the shared secret to finalize
  var ctx = newSha3_256Ctx(sharedSec)
  
  sharedSec.reset()
  vp.reset()
  # alicePrivKey.sk.coeffs.reset() # alice is immutable
  
  return ctx.digest()

############################################################################################

when isMainModule:
  # Alice generates public and private keys
  let (alicePriv, alicePub) = generateKeyPairAlice()

  # Bob derives public and shared keys using Alice's public key
  let (bobPub, bobShared) = keyExchangeBob(alicePub)

  # Alice uses Bobs public key to generate the same shared key as Bob
  let aliceShared = keyExchangeAlice(bobPub, alicePriv)
  
  echo "Alice Key: ", aliceShared.hex()
  echo "Bob Key: ", bobShared.hex()
  doAssert aliceShared == bobShared
