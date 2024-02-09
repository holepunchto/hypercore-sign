#!/usr/bin/env node

const path = require('path')
const fsProm = require('fs/promises')
const os = require('os')
const sodium = require('sodium-native')
const { decode: decodeSigningRequest } = require('hypercore-signing-request')
const z32 = require('z32')

const homeDir = os.homedir()
const secretKeyLoc = path.join(
  homeDir, '.hypercore-sign', 'private-key'
)
const publicKeyLoc = path.join(
  homeDir, '.hypercore-sign', 'public-key'
)

async function main () {
  const z32SigningRequest = process.argv[2]
  if (!z32SigningRequest) {
    console.log('Sign a message. Call as:\nhypercore-sign <z32SigningRequest>')
    process.exit(1)
  }

  const signingRequest = z32.decode(z32SigningRequest)
  try {
    const decodedRequest = decodeSigningRequest(signingRequest)
    console.log('Signing request:')
    console.log(decodedRequest)
  } catch (e) {
    console.log(e)
    console.error('\nCould not decode the signing request. Invalid signing request?')
    process.exit(1)
  }

  const secretKey = z32.decode(
    await fsProm.readFile(secretKeyLoc, 'utf-8')
  )
  const publicKey = z32.decode(
    await fsProm.readFile(publicKeyLoc, 'utf-8')
  )
  const z32PubKey = z32.encode(publicKey)

  const signedMsg = Buffer.alloc(signingRequest.length + sodium.crypto_sign_BYTES)

  sodium.crypto_sign(signedMsg, Buffer.from(signingRequest), secretKey)
  const z32SignedMessage = z32.encode(signedMsg)
  console.log(`\nSigned message:\n${z32SignedMessage}`)

  console.log(`\nVerifiable with pub key: ${z32PubKey}`)
  console.log('\nFull command to verify:')
  console.log(`hypercore-verify ${z32SignedMessage} ${z32PubKey}`)
}

main()
