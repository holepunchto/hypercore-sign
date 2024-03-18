const c = require('compact-encoding')

const { MAX_SUPPORTED_VERSION } = require('./constants')

const partialSignature = {
  preencode (state, s) {
    c.uint.preencode(state, s.signer)
    c.fixed64.preencode(state, s.signature)
    c.uint.preencode(state, s.patch)
  },
  encode (state, s) {
    console.log(s)
    c.uint.encode(state, s.signer)
    c.fixed64.encode(state, s.signature)
    c.uint.encode(state, s.patch)
  },
  decode (state) {
    return {
      signer: c.uint.decode(state),
      signature: c.fixed64.decode(state),
      patch: c.uint.decode(state)
    }
  }
}

const signatureV0 = {
  preencode (state, s) {
    c.fixed64.preencode(state, s.signature)
  },
  encode (state, s) {
    c.fixed64.encode(state, s.signature)
  },
  decode (state) {
    return {
      signature: c.fixed64.decode(state),
    }
  }
}

const signaturesV0 = c.array(signatureV0)
const signatures = c.array(partialSignature)

const Response = {
  preencode (state, res) {
    c.uint.preencode(state, res.version)
    c.fixed32.preencode(state, res.requestHash)
    c.fixed32.preencode(state, res.publicKey)
    signatures.preencode(state, res.signatures)
  },
  encode (state, res) {
    c.uint.encode(state, res.version)
    c.fixed32.encode(state, res.requestHash)
    c.fixed32.encode(state, res.publicKey)
    signatures.encode(state, res.signatures)
  },
  decode (state) {
    const version = c.uint.decode(state)

    if (version > MAX_SUPPORTED_VERSION) {
      throw new Error('Response version is not supported, please upgrade')
    }

    return {
      version,
      requestHash: c.fixed32.decode(state),
      publicKey: c.fixed32.decode(state),
      signatures: version === 1
        ? signaturesV0.decode(state)
        : signatures.decode(state)
    }
  }
}

module.exports = {
  Response
}
