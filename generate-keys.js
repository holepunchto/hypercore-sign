#!/usr/bin/env node

const path = require('path')
const fs = require('fs')
const fsProm = fs.promises
const os = require('os')
const sodium = require('sodium-native')
const z32 = require('z32')

const homeDir = os.homedir()

async function main () {
  const dir = path.join(homeDir, '.hypercore-sign')

  await fsProm.mkdir(dir, { mode: 0o700, recursive: true })
  const secretKeyLoc = path.join(dir, 'private-key')
  const publicKeyLoc = path.join(dir, 'public-key')

  const pubKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  // TODO: consider encrypting the file and reading the pass from stdin for signing
  const secretKey = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(pubKey, secretKey)

  if (fs.existsSync(secretKeyLoc)) {
    throw new Error(`Secret key file already exists at ${secretKeyLoc}`)
  }
  if (fs.existsSync(publicKeyLoc)) {
    throw new Error(`Public key file already exists at ${publicKeyLoc}`)
  }

  await fsProm.writeFile(
    secretKeyLoc,
    z32.encode(secretKey),
    { mode: 0o600 }
  )
  await fsProm.writeFile(
    publicKeyLoc,
    z32.encode(pubKey),
    { mode: 0o600 }
  )

  // Prompt a confirmation when overwriting
  // (Because you probably don't want to overwrite these,
  // once they have been generated)
  fsProm.chmod(publicKeyLoc, 0o400)
  fsProm.chmod(secretKeyLoc, 0o400)

  console.log(`Secret key written to ${secretKeyLoc}`)
  console.log(`Public key written to ${publicKeyLoc}`)
}

main()
