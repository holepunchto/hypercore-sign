#!/usr/bin/env node

const sodium = require('sodium-native')
const idEncoding = require('hypercore-id-encoding')

async function main () {
  const signedMessage = Buffer.from(process.argv[2], 'hex')
  const publicKey = Buffer.from(process.argv[3], 'hex')
  if (!signedMessage || !publicKey) {
    console.log('Verify a signed message. Call as:\nhypercore-verify signedMessage publicKey')
    process.exit(1)
  }

  const reopenedMsg = Buffer.alloc(signedMessage.length - sodium.crypto_sign_BYTES)
  const trusted = sodium.crypto_sign_open(reopenedMsg, signedMessage, publicKey)
  if (!trusted) throw new Error('Invalid signature!')

  console.log('\nThe signature is valid.')
  console.log('\nAuthenticated message:')
  console.log(reopenedMsg.toString())

  const lines = reopenedMsg.toString().split('\n')
  const key = lines[0].split(' ')[1]
  if (!idEncoding.isValid(key)) throw new Error('Invalid message structure (invalid key)')
  const treeHash = lines[2].split(' ')[1]
  if (!idEncoding.isValid(treeHash)) throw new Error('Invalid message structure (invalid treeHash)')
}

main()
