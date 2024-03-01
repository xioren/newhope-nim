import std/[strutils, sysrand]
import params, poly_simple
import private/sha3/sha3_256

#[
  NewHope without reconciliation (NewHope-Simple) is a modified version of the original that
  avoids the reconciliation error-correction scheme
  https://eprint.iacr.org/2016/1157
  based on https://github.com/Yawning/newhope
]#

const
  SharedSecretSize = 32
  HighBytes = 384
  NEWHOPE_SENDBBYTES_SIMPLE = POLY_BYTES + HighBytes

type
  PrivateKeyAlice* = object
    sk*: Poly
  PublicKeyAlice* = object
    send*: array[NEWHOPE_SENDABYTES, byte]
  PublicKeyBob* = object
    send*: array[NEWHOPE_SENDBBYTES_SIMPLE, byte]


############################################################################################

proc hex*(digest: array[SharedSecretSize, byte]): string =
  ## produces a hex string of length digest * 2
  result = newStringOfCap(digest.len + digest.len)
  for b in digest:
    result.add(b.toHex(2).toLowerAscii())

  return result


proc memWipe[T](obj: var openArray[T]) =
  ## this isnt necessary
  for idx in 0 ..< obj.len:
    obj[idx] = default(T)

############################################################################################

proc encodeA(r: var openArray[byte], pk: Poly, seed: openArray[byte]) =
  pk.polyToBytes(r)
  for i in 0 ..< NEWHOPE_SEEDBYTES:
    r[POLY_BYTES + i] = seed[i]


proc decodeA(pk: var Poly, seed: var openArray[byte], r: openArray[byte]) =
  pk.polyFromBytes(r)
  for i in 0 ..< seed.len:
    seed[i] = r[POLY_BYTES + i]


proc encodeBSimple(r: var openArray[byte], b: Poly, v: Poly) =
  ## encodes polynomials `b` and `v` into byte array `r`
  b.polyToBytes(r) # convert polynomial `b` to bytes and store in `r`
  v.compress(r, POLY_BYTES) # compress polynomial `v` and append after `b`'s bytes


proc decodeBSimple(b: var Poly, v: var Poly, r: openArray[byte]) =
  ## decodes byte array `r` into polynomials `b` and `v`
  b.polyFromBytes(r) # convert the first part of `r` into polynomial `b`
  v.decompress(r, POLY_BYTES) # decompress the second part of `r` into polynomial `v`


proc newPublicKeyAlice*(msg: openArray[byte]): PublicKeyAlice =
  if msg.len != NEWHOPE_SENDABYTES:
    raise newException(ValueError, "cannot create key from message of length $1" % $msg.len)
  for i, b in msg:
    result.send[i] = b


proc newPublicKeyBob*(msg: openArray[byte]): PublicKeyBob =
  if msg.len != NEWHOPE_SENDBBYTES_SIMPLE:
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
    seed, noiseSeed: array[NEWHOPE_SEEDBYTES, byte] # seeds for randomnesss
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
  pk.polyAdd(e, r)
  
  # NOTE: encode public key and seed for transmission
  pubKey.send.encodeA(pk, seed)
  
  noiseSeed.reset()
  return (privKey, pubKey)


proc keyExchangeBob*(alicePk: PublicKeyAlice): tuple[pubKey: PublicKeyBob, sharedSec: array[SharedSecretSize, byte]] =
  ## Bob generates his public key and a shared secret key using Alice's public key
  var
    pka, a, sp, ep, u, v, epp, m: Poly # polynomials for key exchange
    seed, noiseSeed: array[NEWHOPE_SEEDBYTES, byte] # seeds for generating polynomials
    pubKey: PublicKeyBob
    sharedSec: array[SharedSecretSize, byte]

  discard urandom(noiseSeed)
  discard urandom(sharedSec)
  
  var ctx = newSha3_256Ctx(sharedSec) 
  sharedSec = ctx.digest() # hash the initial shared secret
  m.fromMsg(sharedSec) # convert hashed shared secret into polynomial `m`

  pka.decodeA(seed, alicePk.send) # decode Alice's public key and seed
  a.polyUniform(seed) # generate uniform polynomial `a` from seed
  
  # NOTE: generate noise polynomials for Bob's private key, error terms
  sp.polyGetNoise(noiseSeed, 0) # noise for Bob's private key
  sp.polyNtt() # convert to NTT domain
  ep.polyGetNoise(noiseSeed, 1) # noise for first error term
  ep.polyNtt() # convert to NTT domain
  
  # NOTE: compute u and v for Bob's public key and shared secret
  u.polyPointwise(a, sp) # u = a*s' + e'
  u.polyAdd(u, ep) # add error term `ep` to `u`

  v.polyPointwise(pka, sp) # v = pka*s' (in NTT domain)
  v.polyInvNtt() # convert `v` back from NTT domain
  
  epp.polyGetNoise(noiseSeed, 2) # additional noise for `v`
  v.polyAdd(v, epp) # add noise `epp` to `v`
  v.polyAdd(v, m) # add message polynomial `m` to `v`
  
  pubKey.send.encodeBSimple(u, v)
  ctx = newSha3_256Ctx(sharedSec)

  noiseSeed.reset()
  sharedSec.reset()
  sp.reset()
  v.reset()
  m.reset()

  return (pubKey, ctx.digest())


proc keyExchangeAlice*(bobPk: PublicKeyBob, aliceSk: PrivateKeyAlice): array[SharedSecretSize, byte] =
  ## Alice generates the shared secret key using Bob's public key
  var
    u, v, m: Poly # polynomials for decoding Bob's public key and computing shared secret
    sharedSec: array[SharedSecretSize, byte]

  # NOTE: decode Bob's public key `u` and compressed polynomial `v` from Bob's message
  u.decodeBSimple(v, bobPk.send)
  
  # NOTE: compute m = u * aliceSk in the NTT domain, representing the shared secret contribution
  m.polyPointwise(aliceSk.sk, u)
  m.polyInvNtt() # Convert `m` back from NTT domain to add with `v`
  
  # NOTE: subtract decoded polynomial `v` from `m` to finalize the shared secret calculation
  m.sub(m, v)
  
  # NOTE: convert the result into a message format to be hashed
  m.toMsg(sharedSec)
  var ctx = newSha3_256Ctx(sharedSec)
  
  sharedSec.reset()
  m.reset()
  # aliceSk.sk.coeffs.reset() # aliceSk is immutable
  return ctx.digest()

############################################################################################

when isMainModule:
  # Alice generates public and private keys
  let (alicePriv, alicePub) = generateKeyPairAlice()

  # Bob derives public and shared keys using Alice's public key
  let (bobPub, bobShared) = keyExchangeBob(alicePub)

  # Alice uses Bobs public and her private key to generate the same shared key as Bob
  let aliceShared = keyExchangeAlice(bobPub, alicePriv)
  
  echo "Alice Key: ", aliceShared.hex()
  echo "Bob Key: ", bobShared.hex()
  doAssert aliceShared == bobShared