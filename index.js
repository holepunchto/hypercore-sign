const c = require('compact-encoding')
const crypto = require('hypercore-crypto')
const request = require('hypercore-signing-request')
const sodium = require('sodium-native')

const { LabelledKey, KeyDescriptor, EncryptedKey } = require('./lib/encoding.js')
const { COMPAT_VERSION, MAX_KEY_VERSION } = require('./lib/constants.js')

function generateKeys(pwd) {
  const id = Buffer.alloc(8)

  const publicKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const salt = Buffer.alloc(32)
  const checkSum = Buffer.alloc(sodium.crypto_generichash_BYTES)

  const secretKey = sodium.sodium_malloc(sodium.crypto_sign_SECRETKEYBYTES)
  const kdfOutput = sodium.sodium_malloc(id.byteLength + secretKey.byteLength + checkSum.byteLength)

  const params = {
    ops: sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE,
    mem: sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE
  }

  sodium.randombytes_buf(id)
  sodium.randombytes_buf(salt)

  sodium.crypto_sign_keypair(publicKey, secretKey)

  const checkSumData = c.encode(LabelledKey, { id, secretKey })
  sodium.crypto_generichash(checkSum, checkSumData)

  free(checkSumData)

  const payload = c.encode(KeyDescriptor, {
    id,
    secretKey,
    checkSum
  })

  free(secretKey)

  sodium.sodium_mprotect_readwrite(pwd)

  try {
    sodium.crypto_pwhash_scryptsalsa208sha256(kdfOutput, pwd, salt, params.ops, params.mem)
  } finally {
    free(pwd)
  }

  try {
    xor(payload, kdfOutput)
  } finally {
    free(kdfOutput)
  }

  const encrypted = c.encode(EncryptedKey, {
    version: MAX_KEY_VERSION,
    params,
    salt,
    payload,
    publicKey
  })

  free(payload)

  return {
    id,
    publicKey,
    secretKey: encrypted
  }
}

function sign(signingRequest, keyBuffer, pwd, publicKey = null) {
  let req = null
  try {
    req = request.decode(signingRequest)
  } catch (err) {
    free(pwd)
    throw new Error('Invalid signing request', { cause: err })
  }

  const requestHash = crypto.hash(signingRequest)

  let key = null
  try {
    key = c.decode(EncryptedKey, keyBuffer)
  } catch {
    free(pwd)
    throw new Error('Invalid key')
  }

  const { version, params, salt, payload } = key

  // version >= 1 has public key stored inline
  if (version > COMPAT_VERSION) publicKey = key.publicKey

  if (version > MAX_KEY_VERSION) {
    free(pwd)
    throw new Error('Key version not supported, please update')
  }

  const kdfOutput = sodium.sodium_malloc(payload.byteLength)

  sodium.sodium_mprotect_readwrite(pwd)
  sodium.sodium_mprotect_readwrite(kdfOutput)

  try {
    sodium.crypto_pwhash_scryptsalsa208sha256(kdfOutput, pwd, salt, params.ops, params.mem)

    xor(payload, kdfOutput)
  } finally {
    free(pwd)
    free(kdfOutput)
  }

  const { id, secretKey, checkSum } = c.decode(KeyDescriptor, payload)

  const checkAgainst = Buffer.alloc(sodium.crypto_generichash_BYTES)
  const checkSumData = c.encode(LabelledKey, { id, secretKey })

  try {
    sodium.crypto_generichash(checkAgainst, checkSumData)

    if (Buffer.compare(checkAgainst, checkSum) !== 0) {
      throw new Error('Key decryption failed')
    }

    const signables = request.signable(publicKey, req)

    const signatures = []
    for (const { signable } of signables) {
      const signature = Buffer.alloc(sodium.crypto_sign_BYTES)
      sodium.crypto_sign_detached(signature, signable, secretKey)
      signatures.push(signature)
    }

    return request.encodeResponse({
      version: req.version,
      requestHash,
      publicKey,
      signatures
    })
  } finally {
    free(checkSumData)
    free(secretKey)
    free(payload)
  }
}

function verify(response, signingRequest, publicKey) {
  let req = null
  let res = null

  try {
    req = request.decode(signingRequest)
    res = request.decodeResponse(response)
  } catch (err) {
    throw new Error('Invalid data', { cause: err })
  }

  if (Buffer.compare(res.requestHash, crypto.hash(signingRequest)) !== 0) {
    throw new Error('Signature was not made over this request')
  }

  if (Buffer.compare(res.publicKey, publicKey) !== 0) {
    throw new Error('Public key does not match')
  }

  const signables = request.signable(publicKey, req)

  if (signables.length !== res.signatures.length) {
    throw new Error('Invalid response: signature count does not match')
  }

  for (let i = 0; i < signables.length; i++) {
    if (!sodium.crypto_sign_verify_detached(res.signatures[i], signables[i].signable, publicKey)) {
      throw new Error('Invalid signature!')
    }
  }

  return req
}

function free(buffer) {
  if (buffer.secure) sodium.sodium_mprotect_readwrite(buffer)
  sodium.sodium_memzero(buffer)
  sodium.sodium_free(buffer)
}

function xor(a, b) {
  if (a.byteLength !== b.byteLength) {
    throw new Error('Buffers should be equal in size')
  }

  for (let i = 0; i < a.length; i++) {
    a[i] ^= b[i]
  }
}

module.exports = {
  generateKeys,
  sign,
  verify,
  free,
  isRequest: request.isRequest,
  isResponse: request.isResponse
}
