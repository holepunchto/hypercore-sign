const c = require('compact-encoding')

const Response = {
  preencode (state, res) {
    c.fixed32.preencode(state, res.requestHash)
    c.fixed32.preencode(state, res.publicKey)
    c.fixed64.preencode(state, res.signature)
  },
  encode (state, res) {
    c.fixed32.encode(state, res.requestHash)
    c.fixed32.encode(state, res.publicKey)
    c.fixed64.encode(state, res.signature)
  },
  decode (state, res) {
    return {
      requestHash: c.fixed32.decode(state),
      publicKey: c.fixed32.decode(state),
      signature: c.fixed64.decode(state)
    }
  }
}

module.exports = {
  Response
}
