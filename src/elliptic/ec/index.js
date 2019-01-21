import BN from 'bn.js'
import HmacDRBG from 'hmac-drbg'
import { assert } from '../utils'
import KeyPair from './key'
import Signature from './signature'
import { secp256k1 } from '../curves'
import rand from 'brorand'

export default class EC {
  constructor () {
    this.curve = secp256k1.curve
    this.n = this.curve.n
    this.nh = this.n.ushrn(1)
    this.g = this.curve.g

    // Point on curve
    this.g = secp256k1.g
    this.g.precompute(secp256k1.n.bitLength() + 1)

    // Hash for function for DRBG
    this.hash = secp256k1.hash
  }

  keyPair (options) {
    return new KeyPair(this, options)
  }

  keyFromPrivate (priv, enc) {
    return KeyPair.fromPrivate(this, priv, enc)
  }

  keyFromPublic (pub, enc) {
    return KeyPair.fromPublic(this, pub, enc)
  }

  genKeyPair (options) {
    if (!options) { options = {}}

    // Instantiate Hmac_DRBG
    var drbg = new HmacDRBG({
      hash: this.hash,
      pers: options.pers,
      persEnc: options.persEnc || 'utf8',
      entropy: options.entropy || rand(192),
      entropyEnc: options.entropy && options.entropyEnc || 'utf8',
      nonce: this.n.toArray()
    })

    var bytes = this.n.byteLength()
    var ns2 = this.n.sub(new BN(2))
    do {
      var priv = new BN(drbg.generate(bytes))
      if (priv.cmp(ns2) > 0) continue

      priv.iaddn(1)
      return this.keyFromPrivate(priv)
    } while (true)
  }

  truncateToN (msg, truncOnly) {
    var delta = msg.byteLength() * 8 - this.n.bitLength()
    if (delta > 0) {
      msg = msg.ushrn(delta)
    }
    if (!truncOnly && msg.cmp(this.n) >= 0) {
      return msg.sub(this.n)
    } else {
      return msg
    }
  }

  sign (msg, key, enc, options) {
    if (typeof enc === 'object') {
      options = enc
      enc = null
    }
    if (!options) {
      options = {}
    }

    key = this.keyFromPrivate(key, enc)
    msg = this.truncateToN(new BN(msg, 16))

    // Zero-extend key to provide enough entropy
    var bytes = this.n.byteLength()
    var bkey = key.getPrivate().toArray('be', bytes)

    // Zero-extend nonce to have the same byte size as N
    var nonce = msg.toArray('be', bytes)

    // Instantiate Hmac_DRBG
    var drbg = new HmacDRBG({
      hash: this.hash,
      entropy: bkey,
      nonce: nonce,
      pers: options.pers,
      persEnc: options.persEnc || 'utf8'
    })

    // Number of bytes to generate
    var ns1 = this.n.sub(new BN(1))

    for (var iter = 0; true; iter++) {
      var k = options.k
        ? options.k(iter)
        : new BN(drbg.generate(this.n.byteLength()))
      k = this.truncateToN(k, true)
      if (k.cmpn(1) <= 0 || k.cmp(ns1) >= 0) continue

      var kp = this.g.mul(k)
      if (kp.isInfinity()) continue

      var kpX = kp.getX()
      var r = kpX.umod(this.n)
      if (r.cmpn(0) === 0) continue

      var s = k.invm(this.n).mul(r.mul(key.getPrivate()).iadd(msg))
      s = s.umod(this.n)
      if (s.cmpn(0) === 0) continue

      var recoveryParam = (kp.getY().isOdd() ? 1 : 0) |
                          (kpX.cmp(r) !== 0 ? 2 : 0)

      // Use complement of `s`, if it is > `n / 2`
      if (options.canonical && s.cmp(this.nh) > 0) {
        s = this.n.sub(s)
        recoveryParam ^= 1
      }

      return new Signature({ r: r, s: s, recoveryParam: recoveryParam })
    }
  };

  verify (msg, signature, key, enc) {
    msg = this.truncateToN(new BN(msg, 16))
    key = this.keyFromPublic(key, enc)
    signature = new Signature(signature, 'hex')

    // Perform primitive values validation
    var r = signature.r
    var s = signature.s
    if (r.cmpn(1) < 0 || r.cmp(this.n) >= 0) return false
    if (s.cmpn(1) < 0 || s.cmp(this.n) >= 0) return false

    // Validate signature
    var sinv = s.invm(this.n)
    var u1 = sinv.mul(msg).umod(this.n)
    var u2 = sinv.mul(r).umod(this.n)

    if (!this.curve._maxwellTrick) {
      var p = this.g.mulAdd(u1, key.getPublic(), u2)
      if (p.isInfinity()) return false

      return p.getX().umod(this.n).cmp(r) === 0
    }

    // NOTE: Greg Maxwell's trick, inspired by:
    // https://git.io/vad3K

    var p = this.g.jmulAdd(u1, key.getPublic(), u2)
    if (p.isInfinity()) return false

    // Compare `p.x` of Jacobian point with `r`,
    // this will do `p.x == r * p.z^2` instead of multiplying `p.x` by the
    // inverse of `p.z^2`
    return p.eqXToP(r)
  }

  recoverPubKey (msg, signature, j, enc) {
    assert((3 & j) === j, 'The recovery param is more than two bits')
    signature = new Signature(signature, enc)

    var n = this.n
    var e = new BN(msg)
    var r = signature.r
    var s = signature.s

    // A set LSB signifies that the y-coordinate is odd
    var isYOdd = j & 1
    var isSecondKey = j >> 1
    if (r.cmp(this.curve.p.umod(this.curve.n)) >= 0 && isSecondKey) throw new Error('Unable to find sencond key candinate')

    // 1.1. Let x = r + jn.
    if (isSecondKey) {
      r = this.curve.pointFromX(r.add(this.curve.n), isYOdd)
    } else {
      r = this.curve.pointFromX(r, isYOdd)
    }

    var rInv = signature.r.invm(n)
    var s1 = n.sub(e).mul(rInv).umod(n)
    var s2 = s.mul(rInv).umod(n)

    // 1.6.1 Compute Q = r^-1 (sR -  eG)
    //               Q = r^-1 (sR + -eG)
    return this.g.mulAdd(s1, r, s2)
  }

  getKeyRecoveryParam (e, signature, Q, enc) {
    signature = new Signature(signature, enc)
    if (signature.recoveryParam !== null) {
      return signature.recoveryParam
    }

    for (var i = 0; i < 4; i++) {
      var Qprime
      try {
        Qprime = this.recoverPubKey(e, signature, i)
      } catch (e) {
        continue
      }

      if (Qprime.eq(Q)) return i
    }
    throw new Error('Unable to find valid recovery factor')
  }
}
