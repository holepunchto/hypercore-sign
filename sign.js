#!/usr/bin/env node

const path = require('path')
const fsProm = require('fs/promises')
const os = require('os')
const request = require('hypercore-signing-request')
const z32 = require('z32')
const c = require('compact-encoding')

const { version } = require('./package.json')
const { readPassword, sign, hash } = require('./lib/secure')
const { Response } = require('./lib/messages')

const homeDir = os.homedir()

async function main () {
  const signingRequest = process.argv[2]
  if (!signingRequest) {
    console.log(`hypercore-sign ${version}\n`)
    console.log('Sign a hypercore signing request.')
    console.log('\nUsage:')
    console.log('hypercore-sign <signingRequest>')
    process.exit(1)
  }

  const keysDir = process.env.HYPERCORE_SIGN_KEYS_DIRECTORY || path.join(homeDir, '.hypercore-sign')

  const secretKeyPath = path.join(keysDir, 'default')
  const publicKeyPath = path.join(keysDir, 'default.public')

  let req = null
  try {
    req = request.decode(z32.decode(signingRequest))
  } catch (e) {
    console.log(e)
    console.error('\nCould not decode the signing request. Invalid signing request?')
    process.exit(1)
  }

  console.log('Signing request:\n')
  console.log(req)
  console.log()

  const requestHash = hash(z32.decode(signingRequest))

  const secretKey = z32.decode(await fsProm.readFile(secretKeyPath, 'utf-8'))
  const publicKey = z32.decode(await fsProm.readFile(publicKeyPath, 'utf-8'))

  const signable = request.signable(publicKey, req)

  const password = await readPassword()
  const signature = sign(signable, secretKey, password)

  const response = c.encode(Response, {
    requestHash,
    publicKey,
    signature
  })

  console.log(`\nSigned with public key:\n\n${z32.encode(publicKey)}`)

  console.log(`\nReply with:\n\n${z32.encode(response)}`)
}

main()
