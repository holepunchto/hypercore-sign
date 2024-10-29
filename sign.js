#!/usr/bin/env node

const path = require('path')
const fsProm = require('fs/promises')
const os = require('os')
const readline = require('readline')
const request = require('hypercore-signing-request')
const z32 = require('z32')
const c = require('compact-encoding')

const { version } = require('./package.json')
const { readPassword, sign, hash } = require('./lib/secure')
const { Response } = require('./lib/messages')
const { MAX_SUPPORTED_VERSION } = require('./lib/constants')

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

  const requestHash = hash(z32.decode(signingRequest))

  const secretKey = z32.decode(await fsProm.readFile(secretKeyPath, 'utf-8'))
  const publicKey = z32.decode(await fsProm.readFile(publicKeyPath, 'utf-8'))

  const signables = request.signable(publicKey, req)

  console.log(`\nSigning with ${secretKeyPath}\n`)
  if (!(await userConfirm())) {
    console.log('\nRequest aborted.')
    process.exit(1)
  }
  console.log()

  // wait a tick before passing on stdin
  await new Promise(setImmediate)

  const password = await readPassword()
  const signatures = await sign(signables, secretKey, password)

  const response = c.encode(Response, {
    version: req.version,
    requestHash,
    publicKey,
    signatures
  })

  console.log(`\nSigned with public key:\n\n${z32.encode(publicKey)}`)

  console.log(`\nReply with:\n\n${z32.encode(response)}`)
}

main()

async function userConfirm (prompt = 'Confirm? [y/N] ') {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  })

  while (true) {
    const answer = await new Promise(resolve => {
      rl.question(prompt, line => {
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

    rl.close()
    return answer
  }
}

function formatHypercoreRequest (req) {
  return {
    core: req.id,
    fork: req.fork,
    length: req.length,
    treeHash: req.treeHash.toString('hex')
  }
}

function formatHyperdriveRequest (req) {
  return {
    key: req.id,
    fork: req.fork,
    metadata: {
      length: req.length,
      treeHash: req.treeHash.toString('hex')
    },
    content: {
      length: req.content.length,
      treeHash: req.content.treeHash.toString('hex')
    }
  }
}

function box (text) {
  const mid = '\u2502 ' + text + ' \u2502'
  const top = '\u250c'.padEnd(mid.length - 1, '\u2500') + '\u2510'
  const btm = '\u2514'.padEnd(mid.length - 1, '\u2500') + '\u2518'

  return [top, mid, btm].join('\n')
}
