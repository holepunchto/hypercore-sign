#!/usr/bin/env node

const sodium = require('sodium-native')
const request = require('hypercore-signing-request')
const z32 = require('z32')
const { version } = require('./package.json')

async function main () {
  const z32signature = process.argv[2]
  const z32request = process.argv[3]
  const z32publicKey = process.argv[4]
  if (!z32signature || !z32request || !z32publicKey) {
    console.log(`hypercore-sign ${version}\n`)
    console.log('Verify a signed message.')
    console.log('\nUsage:')
    console.log('hypercore-sign verify <z32signature> <z32request> <z32publicKey>\n')
    process.exit(1)
  }

  const publicKey = z32.decode(z32publicKey)
  const signature = z32.decode(z32signature)

  let decodedRequest = null
  try {
    decodedRequest = request.decode(z32.decode(z32request))
    console.log('Signing request:')
    console.log(decodedRequest)
  } catch (e) {
    console.log(e)
    console.error('\nCould not decode the signing request. Invalid signing request?')
    process.exit(1)
  }

  const signable = request.signable(publicKey, decodedRequest)
  if (!sodium.crypto_sign_verify_detached(signature, signable, publicKey)) {
    throw new Error('Invalid signature!')
  }

  console.log('\nThe signature is valid.')
  console.log('\nAuthenticated request:')
  console.log(decodedRequest)
  console.log(`Signed by public key ${z32.encode(publicKey)}`)
}

main()
