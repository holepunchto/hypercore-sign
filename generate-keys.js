#!/usr/bin/env node

const path = require('path')
const fs = require('fs')
const fsProm = fs.promises
const os = require('os')
const z32 = require('z32')

const homeDir = os.homedir()

const { readPassword, generateKeys, confirmPassword } = require('./secure')

async function main () {
  const dir = process.env.HYPERCORE_SIGN_KEYS_DIRECTORY || path.join(homeDir, '.hypercore-sign')

  await fsProm.mkdir(dir, { mode: 0o700, recursive: true })
  const secretKeyLoc = path.join(dir, 'default')
  const publicKeyLoc = path.join(dir, 'default.public')

  if (fs.existsSync(secretKeyLoc)) {
    console.log(`Secret key already written to ${secretKeyLoc}`)
    console.log(`Public key already written to ${publicKeyLoc}`)
    console.log()
    console.log('Public key is', fs.readFileSync(publicKeyLoc, 'utf8'))
    return
  }

  const password = await readPassword()

  if (!(await confirmPassword(password))) {
    console.log('Passwords do not match')
    process.exit(1)
  }

  const { secretKey, publicKey } = generateKeys(password)

  await fsProm.writeFile(
    secretKeyLoc,
    z32.encode(secretKey),
    { mode: 0o600 }
  )

  await fsProm.writeFile(
    publicKeyLoc,
    z32.encode(publicKey),
    { mode: 0o600 }
  )

  // Prompt a confirmation when overwriting
  // (Because you probably don't want to overwrite these,
  // once they have been generated)
  await fsProm.chmod(secretKeyLoc, 0o400)

  console.log(`Secret key written to ${secretKeyLoc}`)
  console.log(`Public key written to ${publicKeyLoc}`)
  console.log()
  console.log('Public key is', z32.encode(publicKey))
}

main()
