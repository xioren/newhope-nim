import params


const
  qinv = 12287'u32  # -inverse_mod(p,2^18)
  rlog = 18'u32


proc montgomeryReduce*(a: uint32): uint16 =
  ## montgomery reduction to bring `a` modulo PARAM_Q
  var aa = a
  var u = aa * qinv
  u = u and ((1 shl rlog) - 1) # compute intermediary value `u`
  u *= PARAM_Q # adjust `u` by multiplying with PARAM_Q
  aa += u # add adjusted `u` to `a` for reduction
  return uint16(aa shr rlog) # shift right to complete reduction, cast to uint16


proc barrettReduce*(a: uint16): uint16 =
  ## barrett reduction to reduce `a` modulo PARAM_Q
  var aa = a
  var u = (uint32(aa) * 5) shr 16 # calculate reduction factor `u`
  u *= PARAM_Q # scale `u` by PARAM_Q
  aa -= uint16(u) # subtract `u` from `a` to reduce modulo PARAM_Q
  return aa