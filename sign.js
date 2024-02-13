#!/usr/bin/env node

const path = require('path')
const fsProm = require('fs/promises')
const os = require('os')
const request = require('hypercore-signing-request')
const z32 = require('z32')
const { version } = require('./package.json')

const homeDir = os.homedir()
const { readPassword, sign } = require('./lib/secure')

async function main () {
  const z32SigningRequest = process.argv[2]
  if (!z32SigningRequest) {
    console.log(`hypercore-sign ${version}\n`)
    console.log('Sign a hypercore signing request.')
    console.log('\nUsage:')
    console.log('hypercore-sign <z32SigningRequest>')
    process.exit(1)
  }

  const keysDir = process.env.HYPERCORE_SIGN_KEYS_DIRECTORY || path.join(homeDir, '.hypercore-sign')
  const secretKeyLoc = path.join(
    keysDir, 'default'
  )
  const publicKeyLoc = path.join(
    keysDir, 'default.public'
  )

  const signingRequest = z32.decode(z32SigningRequest)
  let decodedRequest = null
  try {
    decodedRequest = request.decode(signingRequest)
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
  const signable = request.signable(publicKey, decodedRequest)

  const password = await readPassword()
  const signature = sign(signable, secretKey, password)

  const z32signature = z32.encode(signature)
  console.log(`\nSignature:\n${z32signature}`)

  console.log(`\nVerifiable with pub key: ${z32PubKey}`)
  console.log('\nFull command to verify:')
  console.log(`hypercore-verify ${z32signature} ${z32SigningRequest} ${z32PubKey}`)
}

main()
