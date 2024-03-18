#!/usr/bin/env node

const sodium = require('sodium-native')
const request = require('hypercore-signing-request')
const z32 = require('z32')
const c = require('compact-encoding')

const { version } = require('./package.json')
const { Response } = require('./lib/messages')
const { hash } = require('./lib/secure')
const { MAX_SUPPORTED_VERSION } = require('./lib/constants')

async function main () {
  const response = process.argv[2]
  const signingRequest = process.argv[3]
  const pubkey = process.argv[4]
  if (!response || !signingRequest || !pubkey) {
    console.log(`hypercore-verify ${version}\n`)
    console.log('Verify a signed message.')
    console.log('\nUsage:')
    console.log('hypercore-verify <response> <signingRequest> <pubkey>\n')
    process.exit(1)
  }

  const res = c.decode(Response, z32.decode(response))
  const publicKey = z32.decode(pubkey)

  let req = null
  try {
    req = request.decode(z32.decode(signingRequest))
  } catch (e) {
    console.error('\nCould not decode the signing request. Invalid signing request?')
    process.exit(1)
  }

  if (req.version > MAX_SUPPORTED_VERSION) {
    throw new Error('Request version not supported, please update')
  }

  if (Buffer.compare(res.requestHash, hash(z32.decode(signingRequest))) !== 0) {
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

  console.log('\nSignature verified.')
  console.log(`\n${z32.encode(publicKey)} has signed the following request:`)
  console.log({
    core: req.id,
    fork: req.fork,
    length: req.length,
    treeHash: req.treeHash.toString('hex')
  })
}

main()
