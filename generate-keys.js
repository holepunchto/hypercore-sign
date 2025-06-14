#!/usr/bin/env node

const path = require('path')
const fs = require('fs')
const fsProm = fs.promises
const os = require('os')
const z32 = require('z32')

const homeDir = os.homedir()

// fs permissions
const USER_ONLY_R = 0o400
const USER_ONLY_RW = 0o600
const USER_ONLY_RWX = 0o700

const { generateKeys } = require('./lib/secure')
const { readPassword, confirmPassword } = require('./lib/password')

async function main () {
  const dir = process.env.HYPERCORE_SIGN_KEYS_DIRECTORY || path.join(homeDir, '.hypercore-sign')

  await fsProm.mkdir(dir, { mode: USER_ONLY_RWX, recursive: true })
  const secretKeyPath = path.join(dir, 'default')
  const publicKeyPath = path.join(dir, 'default.public')

  if (fs.existsSync(secretKeyPath)) {
    console.log(`Secret key already written to ${secretKeyPath}`)
    console.log(`Public key already written to ${publicKeyPath}`)
    console.log()
    console.log('Public key is', fs.readFileSync(publicKeyPath, 'utf8'))
    return
  }

  console.log('Your secret key will be encrypted with a password.')
  console.log('Please choose one now:\n')
  const password = await readPassword()

  if (!(await confirmPassword(password))) {
    console.log('Passwords do not match')
    process.exit(1)
  }

  const { secretKey, publicKey } = generateKeys(password)

  // Prompt a confirmation when overwriting
  // (Because you probably don't want to overwrite these,
  // once they have been generated)

  await fsProm.writeFile(secretKeyPath, z32.encode(secretKey), {
    mode: USER_ONLY_R
  })

  await fsProm.writeFile(publicKeyPath, z32.encode(publicKey), {
    mode: USER_ONLY_RW
  })

  console.log(`\nSecret key written to ${secretKeyPath}`)
  console.log(`Public key written to ${publicKeyPath}`)
  console.log()
  console.log('Public key is', z32.encode(publicKey))
}

main()
