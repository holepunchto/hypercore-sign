#!/usr/bin/env node

const sodium = require('sodium-native')
const { decode: decodeSigningRequest } = require('hypercore-signing-request')
const z32 = require('z32')

async function main () {
  const z32signedMessage = process.argv[2]
  const z32publicKey = process.argv[3]
  if (!z32signedMessage || !z32publicKey) {
    console.log('Verify a signed message. Call as:\nhypercore-verify <z32SignedMessage> <z32PublicKey>')
    process.exit(1)
  }

  const signedMessage = z32.decode(z32signedMessage)
  const publicKey = z32.decode(z32publicKey)

  const reopenedMsg = Buffer.alloc(signedMessage.length - sodium.crypto_sign_BYTES)
  const trusted = sodium.crypto_sign_open(reopenedMsg, signedMessage, publicKey)
  if (!trusted) throw new Error('Invalid signature!')

  console.log('\nThe signature is valid.')
  console.log('\nAuthenticated request:')
  const decodedRequest = decodeSigningRequest(reopenedMsg)
  console.log(decodedRequest)
  console.log(`Signed by public key ${z32.encode(publicKey)}`)
}

main()
