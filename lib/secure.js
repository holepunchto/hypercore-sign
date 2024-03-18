const sodium = require('sodium-native')
const securePrompt = require('secure-prompt')
const c = require('compact-encoding')

const MIN_PASSWORD_LENGTH = 8

const labelledKey = {
  preencode (state, k) {
    c.fixed(8).preencode(state, k.id)
    c.fixed64.preencode(state, k.secretKey)
  },
  encode (state, k) {
    c.fixed(8).encode(state, k.id)
    c.fixed64.encode(state, k.secretKey)
  },
  decode (state) {
    throw new Error('No decoder')
  }
}

const keyDescriptor = {
  preencode (state, s) {
    c.fixed(8).preencode(state, s.id)
    c.fixed64.preencode(state, s.secretKey)
    c.fixed32.preencode(state, s.checkSum)
  },
  encode (state, s) {
    c.fixed(8).encode(state, s.id)
    c.fixed64.encode(state, s.secretKey)
    c.fixed32.encode(state, s.checkSum)
  },
  decode (state) {
    return {
      id: c.fixed(8).decode(state),
      secretKey: c.fixed64.decode(state),
      checkSum: c.fixed32.decode(state)
    }
  }
}

const kdfParams = {
  preencode (state, p) {
    c.uint64.preencode(state, p.ops)
    c.uint64.preencode(state, p.mem)
  },
  encode (state, p) {
    c.uint64.encode(state, p.ops)
    c.uint64.encode(state, p.mem)
  },
  decode (state) {
    return {
      ops: c.uint64.decode(state),
      mem: c.uint64.decode(state)
    }
  }
}

const encryptedKey = {
  preencode (state, s) {
    kdfParams.preencode(state, s.params)
    c.fixed32.preencode(state, s.salt)
    c.buffer.preencode(state, s.payload)
  },
  encode (state, s) {
    kdfParams.encode(state, s.params)
    c.fixed32.encode(state, s.salt)
    c.buffer.encode(state, s.payload)
  },
  decode (state) {
    return {
      params: kdfParams.decode(state),
      salt: c.fixed32.decode(state),
      payload: c.buffer.decode(state)
    }
  }
}

module.exports = {
  generateKeys,
  sign,
  confirmPassword,
  readPassword,
  hash
}

function generateKeys (pwd) {
  const id = Buffer.alloc(8)

  const publicKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)

  const salt = Buffer.alloc(32)
  const kdfOutput = Buffer.alloc(8 + 64 + 32)
  const checkSum = Buffer.alloc(sodium.crypto_generichash_BYTES)

  const params = {
    ops: sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE,
    mem: sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE
  }

  sodium.randombytes_buf(id)
  sodium.randombytes_buf(salt)

  sodium.crypto_sign_keypair(publicKey, secretKey)

  const checkSumData = c.encode(labelledKey, { id, secretKey })

  sodium.crypto_generichash(checkSum, checkSumData)
  sodium.sodium_memzero(checkSumData)

  const payload = c.encode(keyDescriptor, {
    id,
    secretKey,
    checkSum
  })

  sodium.sodium_memzero(secretKey)

  sodium.sodium_mprotect_readwrite(pwd)
  sodium.crypto_pwhash_scryptsalsa208sha256(kdfOutput, pwd, salt, params.ops, params.mem)
  sodium.sodium_memzero(pwd)
  sodium.sodium_free(pwd)

  xor(payload, kdfOutput)
  sodium.sodium_memzero(kdfOutput)

  const encrypted = c.encode(encryptedKey, {
    params,
    salt,
    payload
  })

  sodium.sodium_memzero(payload)

  return {
    id,
    publicKey,
    secretKey: encrypted
  }
}

async function confirmPassword (pwd) {
  const check = await readPassword('Confirm password: ')

  if (pwd.byteLength !== check.byteLength) return false

  sodium.sodium_mprotect_readonly(pwd)
  sodium.sodium_mprotect_readwrite(check)

  const cmp = sodium.sodium_memcmp(pwd, check)

  sodium.sodium_memzero(check)
  sodium.sodium_free(check)

  sodium.sodium_mprotect_noaccess(pwd)

  return cmp
}

function sign (signables, keyBuffer, pwd) {
  const { params, salt, payload } = c.decode(encryptedKey, keyBuffer)

  const kdfOutput = Buffer.alloc(8 + 64 + 32)

  sodium.sodium_mprotect_readwrite(pwd)
  sodium.crypto_pwhash_scryptsalsa208sha256(kdfOutput, pwd, salt, params.ops, params.mem)
  sodium.sodium_memzero(pwd)
  sodium.sodium_free(pwd)

  xor(payload, kdfOutput)
  sodium.sodium_memzero(kdfOutput)

  const { id, secretKey, checkSum } = c.decode(keyDescriptor, payload)

  const checkAgainst = Buffer.alloc(sodium.crypto_generichash_BYTES)
  const checkSumData = c.encode(labelledKey, { id, secretKey })

  sodium.crypto_generichash(checkAgainst, checkSumData)
  sodium.sodium_memzero(checkSumData)

  if (Buffer.compare(checkAgainst, checkSum) !== 0) {
    sodium.sodium_memzero(secretKey)
    sodium.sodium_memzero(payload)
    throw new Error('Key decryption failed')
  }

  const signatures = []
  for (const { signable } of signables) {
    const signature = Buffer.alloc(sodium.crypto_sign_BYTES)
    sodium.crypto_sign_detached(signature, signable, secretKey)
    signatures.push(signature)
  }

  sodium.sodium_memzero(secretKey)
  sodium.sodium_memzero(payload)

  return signatures
}

// function to accept password from user
async function readPassword (prompt = 'Keypair password: ') {
  process.stdout.write(prompt)

  const pwd = await securePrompt()

  console.log()

  if (pwd.byteLength < MIN_PASSWORD_LENGTH) {
    throw new Error(`Password must be at least ${MIN_PASSWORD_LENGTH} characters`)
  }

  return pwd
}

function hash (data) {
  const output = Buffer.alloc(sodium.crypto_generichash_BYTES)
  sodium.crypto_generichash(output, data)

  return output
}

function xor (a, b) {
  if (a.byteLength !== b.byteLength) {
    throw new Error('Buffers should be equal in size')
  }

  for (let i = 0; i < a.length; i++) {
    a[i] ^= b[i]
  }
}
