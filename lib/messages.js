const c = require('compact-encoding')

const { MAX_SUPPORTED_VERSION } = require('./constants')

const Response = {
  preencode (state, res) {
    c.uint.preencode(state, res.version)
    c.fixed32.preencode(state, res.requestHash)
    c.fixed32.preencode(state, res.publicKey)
    c.fixed64.preencode(state, res.signature)
  },
  encode (state, res) {
    c.uint.encode(state, res.version)
    c.fixed32.encode(state, res.requestHash)
    c.fixed32.encode(state, res.publicKey)
    c.fixed64.encode(state, res.signature)
  },
  decode (state, res) {
    const version = c.uint.decode(state)

    if (version > MAX_SUPPORTED_VERSION) {
      throw new Error('Response version is not supported, please upgrade')
    }

    return {
      version,
      requestHash: c.fixed32.decode(state),
      publicKey: c.fixed32.decode(state),
      signature: c.fixed64.decode(state)
    }
  }
}

module.exports = {
  Response
}
