const c = require('compact-encoding')

const { MAX_REQUEST_VERSION } = require('./constants')

const LabelledKey = {
  preencode(state, k) {
    c.fixed(8).preencode(state, k.id)
    c.fixed64.preencode(state, k.secretKey)
  },
  encode(state, k) {
    c.fixed(8).encode(state, k.id)
    c.fixed64.encode(state, k.secretKey)
  },
  decode(state) {
    throw new Error('No decoder')
  }
}

const KeyDescriptor = {
  preencode(state, s) {
    c.fixed(8).preencode(state, s.id)
    c.fixed64.preencode(state, s.secretKey)
    c.fixed32.preencode(state, s.checkSum)
  },
  encode(state, s) {
    c.fixed(8).encode(state, s.id)
    c.fixed64.encode(state, s.secretKey)
    c.fixed32.encode(state, s.checkSum)
  },
  decode(state) {
    return {
      id: c.fixed(8).decode(state),
      secretKey: c.fixed64.decode(state),
      checkSum: c.fixed32.decode(state)
    }
  }
}

const KdfParams = {
  preencode(state, p) {
    c.uint64.preencode(state, p.ops)
    c.uint64.preencode(state, p.mem)
  },
  encode(state, p) {
    c.uint64.encode(state, p.ops)
    c.uint64.encode(state, p.mem)
  },
  decode(state) {
    return {
      ops: c.uint64.decode(state),
      mem: c.uint64.decode(state)
    }
  }
}

const EncryptedKey = {
  preencode(state, s) {
    c.uint.preencode(state, s.version)
    KdfParams.preencode(state, s.params)
    c.fixed32.preencode(state, s.salt)
    c.buffer.preencode(state, s.payload)
    c.fixed32.preencode(state, s.publicKey)
  },
  encode(state, s) {
    c.uint.encode(state, s.version)
    KdfParams.encode(state, s.params)
    c.fixed32.encode(state, s.salt)
    c.buffer.encode(state, s.payload)
    c.fixed32.encode(state, s.publicKey)
  },
  decode(state) {
    return {
      version: c.uint.decode(state),
      params: KdfParams.decode(state),
      salt: c.fixed32.decode(state),
      payload: c.buffer.decode(state),
      publicKey: c.fixed32.decode(state)
    }
  }
}

const Signatures = c.array(c.fixed64)

const Response = {
  preencode(state, res) {
    c.uint.preencode(state, res.version)
    c.fixed32.preencode(state, res.requestHash)
    c.fixed32.preencode(state, res.publicKey)
    Signatures.preencode(state, res.signatures)
  },
  encode(state, res) {
    c.uint.encode(state, res.version)
    c.fixed32.encode(state, res.requestHash)
    c.fixed32.encode(state, res.publicKey)
    Signatures.encode(state, res.signatures)
  },
  decode(state, res) {
    const version = c.uint.decode(state)

    if (version > MAX_REQUEST_VERSION) {
      throw new Error('Response version is not supported, please upgrade')
    }

    return {
      version,
      requestHash: c.fixed32.decode(state),
      publicKey: c.fixed32.decode(state),
      signatures: Signatures.decode(state)
    }
  }
}

module.exports = {
  LabelledKey,
  KdfParams,
  KeyDescriptor,
  EncryptedKey,
  Signatures,
  Response
}
