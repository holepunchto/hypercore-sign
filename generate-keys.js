#!/usr/bin/env node

const path = require('path')
const fsProm = require('fs/promises')
const os = require('os')
const sodium = require('sodium-native')

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

  await fsProm.writeFile(
    secretKeyLoc,
    secretKey.toString('hex'),
    { mode: 0o600 }
  )
  await fsProm.writeFile(
    publicKeyLoc,
    pubKey.toString('hex'),
    { mode: 0o600 }
  )

  // Make fail when overwriting from within node
  // and prompt a confirmation when overwriting from bash
  // (Because you probably don't want to overwrite these,
  // once they have been generated)
  fsProm.chmod(publicKeyLoc, 0o400)
  fsProm.chmod(secretKeyLoc, 0o400)

  console.log(`Secret key written to ${secretKeyLoc}`)
  console.log(`Public key written to ${publicKeyLoc}`)
}

main()
