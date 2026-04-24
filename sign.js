#!/usr/bin/env node

const path = require('path')
const fsProm = require('fs/promises')
const os = require('os')
const readline = require('readline')
const { MAX_SUPPORTED_VERSION, sign, getKeyInfo } = require('hypercore-sign-lib')
const request = require('hypercore-signing-request')
const z32 = require('z32')
const b4a = require('b4a')

const { version } = require('./package.json')
const { readPassword } = require('./lib/password')
const { USER_ONLY_R, USER_ONLY_RW } = require('./lib/permissions')
const { migrateV3 } = require('./migrations/v3')

const homeDir = os.homedir()

const V3_KEY_VERSION = 0 // legacy key version

async function main() {
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

  console.log('Using keys from directory:', keysDir, '\n')

  const secretKey = z32.decode(await fsProm.readFile(secretKeyPath, 'utf-8'))
  const publicKey = z32.decode(await fsProm.readFile(publicKeyPath, 'utf-8'))

  const info = getKeyInfo(secretKey)

  if (info.version === V3_KEY_VERSION) {
    console.log('Found legacy key at:', secretKeyPath)

    if (await userConfirm('Would you like to upgrade? [y/N]')) {
      console.log('Migrating keys...')
      await migrateKeys(secretKey, publicKey, secretKeyPath)

      console.log('Keys migrated successfully. Please run your request again.')
      process.exit(0)
    }
  }

  console.log('hello')

  let req = null
  try {
    req = request.decode(z32.decode(signingRequest))
  } catch (e) {
    console.log(e)
    console.error('\nCould not decode the signing request. Invalid signing request?')
    process.exit(1)
  }

  if (req.version > MAX_SUPPORTED_VERSION) {
    throw new Error('Request version not supported, please update')
  }

  if (req.isHyperdrive) {
    console.log(box('Hyperdrive signing request'))
    console.log(formatHyperdriveRequest(req))
  } else {
    console.log(box('Hypercore signing request'))
    console.log(formatHypercoreRequest(req))
  }
  console.log()

  if (!(await userConfirm())) {
    console.log('\nRequest aborted.')
    process.exit(1)
  }

  console.log('\nRequest data is confirmed')
  console.log('Proceeding to sign...')

  console.log(`\nSigning with ${secretKeyPath}\n`)
  if (!(await userConfirm())) {
    console.log('\nRequest aborted.')
    process.exit(1)
  }
  console.log()

  const password = await readPassword()
  const response = await sign(z32.decode(signingRequest), secretKey, password, publicKey)

  console.log(`\nSigned with public key:\n\n${z32.encode(publicKey)}`)

  console.log(`\nReply with:\n\n${z32.encode(response)}`)
}

main()

async function userConfirm(prompt = 'Confirm? [y/N] ') {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  })

  while (true) {
    const answer = await new Promise((resolve) => {
      rl.question(prompt, (line) => {
        if (!line.length) return resolve(false)

        const key = line[0].toLowerCase()

        switch (key) {
          case 'y':
            resolve(true)
            break

          case 'n':
            resolve(false)
            break

          default:
            prompt = '\nAnswer with y[es] or n[o]: '
            resolve(null)
        }
      })
    })

    if (answer === null) continue

    await new Promise((resolve) => {
      rl.once('close', resolve)
      rl.close()
    })

    // wait tick for stdin to release
    await new Promise(setImmediate)

    return answer
  }
}

async function migrateKeys(secretKey, publicKey, secretKeyPath) {
  const migrated = await migrateV3(secretKey, publicKey)

  const backupSecretKey = backupPath(secretKeyPath, 'v3')

  let copied = false
  try {
    await fsProm.copyFile(secretKeyPath, backupSecretKey)
    copied = true

    console.log('Writing new keys to:', secretKeyPath)

    await fsProm.chmod(secretKeyPath, USER_ONLY_RW)
    await fsProm.writeFile(secretKeyPath, migrated, {
      mode: USER_ONLY_R
    })

    // need to set manuall in case file existed already
    await fsProm.chmod(secretKeyPath, USER_ONLY_R)
  } catch (err) {
    if (copied) {
      try {
        await fsProm.copyFile(backupSecretKey, secretKeyPath)
      } catch {
        console.log('Migration failed: please restore keys from:', backupSecretKey)
      }
    }

    throw new Error('Migration failed')
  }
}

function backupPath(filePath, version) {
  if (!version) throw new Error('Must specify version')
  return filePath + '.' + version + '.backup'
}

function formatHypercoreRequest(req) {
  return {
    core: req.id,
    fork: req.fork,
    length: req.length,
    treeHash: b4a.toString(req.treeHash, 'hex')
  }
}

function formatHyperdriveRequest(req) {
  return {
    key: req.id,
    fork: req.fork,
    metadata: {
      length: req.length,
      treeHash: b4a.toString(req.treeHash, 'hex')
    },
    content: {
      length: req.content.length,
      treeHash: b4a.toString(req.content.treeHash, 'hex')
    }
  }
}

function box(text) {
  const mid = '\u2502 ' + text + ' \u2502'
  const top = '\u250c'.padEnd(mid.length - 1, '\u2500') + '\u2510'
  const btm = '\u2514'.padEnd(mid.length - 1, '\u2500') + '\u2518'

  return [top, mid, btm].join('\n')
}
