import BN from 'bn.js'
import { assert } from '../utils'

export default class KeyPair {
  constructor (ec, options) {
    this.ec = ec
    this.priv = null
    this.pub = null

    // KeyPair(ec, { priv: ..., pub: ... })
    if (options.priv) this._importPrivate(options.priv, options.privEnc)
    if (options.pub) this._importPublic(options.pub, options.pubEnc)
  }

  static fromPublic (ec, pub, enc) {
    if (pub instanceof KeyPair) return pub

    return new KeyPair(ec, {
      pub: pub,
      pubEnc: enc
    })
  };

  static fromPrivate (ec, priv, enc) {
    if (priv instanceof KeyPair) return priv

    return new KeyPair(ec, {
      priv: priv,
      privEnc: enc
    })
  };

  validate () {
    var pub = this.getPublic()
    if (pub.isInfinity()) {
      return { result: false, reason: 'Invalid public key' }
    }
    if (!pub.validate()) {
      return { result: false, reason: 'Public key is not a point' }
    }
    if (!pub.mul(this.ec.curve.n).isInfinity()) {
      return { result: false, reason: 'Public key * N != O' }
    }

    return { result: true, reason: null }
  };

  getPublic (compact, enc) {
    // compact is optional argument
    if (typeof compact === 'string') {
      enc = compact
      compact = null
    }

    if (!this.pub) this.pub = this.ec.g.mul(this.priv)

    if (!enc) return this.pub

    return this.pub.encode(enc, compact)
  };

  getPrivate (enc) {
    if (enc === 'hex') {
      return this.priv.toString(16, 2)
    } else {
      return this.priv
    }
  };

  _importPrivate (key, enc) {
    this.priv = new BN(key, enc || 16)

    // Ensure that the priv won't be bigger than n, otherwise we may fail
    // in fixed multiplication method
    this.priv = this.priv.umod(this.ec.curve.n)
  };

  _importPublic (key, enc) {
    if (key.x || key.y) {
      // Montgomery points only have an `x` coordinate.
      // Weierstrass/Edwards points on the other hand have both `x` and
      // `y` coordinates.
      if (this.ec.curve.type === 'mont') {
        assert(key.x, 'Need x coordinate')
      } else if (this.ec.curve.type === 'short' ||
                this.ec.curve.type === 'edwards') {
        assert(key.x && key.y, 'Need both x and y coordinate')
      }
      this.pub = this.ec.curve.point(key.x, key.y)
      return
    }
    this.pub = this.ec.curve.decodePoint(key, enc)
  };

  // ECDH
  derive (pub) {
    return pub.mul(this.priv).getX()
  };

  // ECDSA
  sign (msg, enc, options) {
    return this.ec.sign(msg, this, enc, options)
  };

  verify (msg, signature) {
    return this.ec.verify(msg, signature, this)
  };

  inspect () {
    return '<Key priv: ' + (this.priv && this.priv.toString(16, 2)) +
          ' pub: ' + (this.pub && this.pub.inspect()) + ' >'
  }
}
