const sodium = require('sodium-native')
const crypto = require('hypercore-crypto')
const request = require('hypercore-signing-request')
const z32 = require('z32')
const c = require('compact-encoding')

const { Response } = require('./messages')
const { MAX_SUPPORTED_VERSION } = require('./constants')

async function verify (response, signingRequest, pubkey) {
  const res = c.decode(Response, z32.decode(response))
  const publicKey = z32.decode(pubkey)

  if (!response || !signingRequest || !pubkey) {
    throw new Error('Invalid arguments')
  }

  let req = null
  try {
    req = request.decode(z32.decode(signingRequest))
  } catch (e) {
    throw new Error('Invalid signing request')
  }

  if (req.version > MAX_SUPPORTED_VERSION) {
    throw new Error('Request version not supported, please update')
  }

  if (Buffer.compare(res.requestHash, crypto.hash(z32.decode(signingRequest))) !== 0) {
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

module.exports = verify
