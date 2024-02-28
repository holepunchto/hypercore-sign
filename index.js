const path = require('path')
const fs = require('fs')
const fsProm = require('fs/promises')
const hypercoreRequest = require('hypercore-signing-request')
const z32 = require('z32')
const sodium = require('sodium-native')
const c = require('compact-encoding')

const { Response } = require('./lib/messages')
const { MAX_SUPPORTED_VERSION } = require('./lib/constants')

const {
  sign,
  hash,
  generateKeys,
  readPassword,
  confirmPassword
} = require('./lib/secure')

const {
  userPrompt,
  userConfirm,
  box,
  formatHypercoreRequest,
  formatHyperdriveRequest
} = require('./lib/utils')

// fs permissions
const USER_ONLY_R = 0o400
const USER_ONLY_RW = 0o600
const USER_ONLY_RWX = 0o700

module.exports = {
  generator,
  signer,
  verifier,
  add
}

async function generator (dir) {
  const name = await userPrompt('\nChoose a name for this key pair: (default) ', 'default')

  await fsProm.mkdir(dir, { mode: USER_ONLY_RWX, recursive: true })

  const secretKeyPath = path.resolve(path.format({ dir, name }))
  const publicKeyPath = path.resolve(path.format({ dir, name, ext: '.public' }))

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
    console.error('Passwords do not match')
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

async function signer (signingRequest, keyPath) {
  let request = null
  let req = null

  try {
    request = z32.decode(signingRequest)
    req = hypercoreRequest.decode(request)
  } catch (e) {
    throw new Error('\nCould not decode the signing request. Invalid signing request?')
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

  const secretKeyPath = path.resolve(path.format(keyPath))
  const publicKeyPath = path.resolve(path.format({ ...keyPath, ext: '.public' }))

  const secretKey = z32.decode(await fsProm.readFile(secretKeyPath, 'utf-8'))
  const publicKey = z32.decode(await fsProm.readFile(publicKeyPath, 'utf-8'))

  const signables = hypercoreRequest.signable(publicKey, req)

  console.log(`\nSigning with ${secretKeyPath}\n`)
  if (!(await userConfirm())) {
    console.error('\nRequest aborted.')
    process.exit(1)
  }
  console.log()

  // wait a tick before passing on stdin
  await new Promise(setImmediate)

  const password = await readPassword()
  const signatures = sign(signables, secretKey, password)

  const response = c.encode(Response, {
    version: req.version,
    requestHash: hash(request),
    publicKey,
    signatures
  })

  console.log(`\nSigned with public key:\n\n${z32.encode(publicKey)}`)
  console.log(`\nReply with:\n\n${z32.encode(response)}`)
}

async function verifier (response, signingRequest, pubkey) {
  const res = c.decode(Response, z32.decode(response))

  let req = null
  try {
    req = hypercoreRequest.decode(z32.decode(signingRequest))
  } catch (e) {
    throw new Error('\nCould not decode the signing request. Invalid signing request?')
  }

  if (req.version > MAX_SUPPORTED_VERSION) {
    throw new Error('Request version not supported, please update')
  }

  if (Buffer.compare(res.requestHash, hash(z32.decode(signingRequest))) !== 0) {
    throw new Error('Signature was not made over this request')
  }

  let known = null
  if (typeof pubkey !== 'string') {
    const keyPath = pubkey.name === ''
      ? path.resolve(path.format(pubkey), 'known-peers')
      : path.resolve(path.format(pubkey))

    let stat
    try {
      stat = await fsProm.stat(keyPath)
    } catch (err) {
      if (err.code !== 'ENOENT') throw err
      throw new Error('No keys found at path: ' + keyPath)
    }

    if (stat.isFile()) {
      known = keyPath
      pubkey = await fsProm.readFile(keyPath, 'utf8')
    } else if (stat.isDirectory()) {
      known = false

      const dir = await fsProm.readdir(keyPath)
      const check = z32.encode(res.publicKey)

      for (const file of dir) {
        const keyFile = path.join(keyPath, file)
        const peer = await fsProm.readFile(keyFile, 'utf8')
        if (peer === check) {
          known = keyFile
          pubkey = peer
          break
        }
        pubkey = null
      }
    }
  }

  if (!pubkey) {
    throw new Error('No corresponding public key could be found')
  }

  const publicKey = z32.decode(pubkey)

  const signables = hypercoreRequest.signable(publicKey, req)

  if (signables.length !== res.signatures.length) {
    throw new Error('Invalid response: signature count does not match')
  }

  if (Buffer.compare(res.publicKey, publicKey) !== 0) {
    throw new Error('Public key does not match')
  }

  for (let i = 0; i < signables.length; i++) {
    if (!sodium.crypto_sign_verify_detached(res.signatures[i], signables[i], publicKey)) {
      throw new Error('Invalid signature!')
    }
  }

  console.log('\nSignature verified.')
  if (known) console.log('\nSigned by known peer:', known)
  console.log(`\n${z32.encode(publicKey)} has signed the following request:`)
  console.log({
    core: req.id,
    fork: req.fork,
    length: req.length,
    treeHash: req.treeHash.toString('hex')
  })
}

async function add (pubkey, dir, name) {
  const publicKey = z32.decode(pubkey)

  if (publicKey.byteLength !== sodium.crypto_sign_PUBLICKEYBYTES) {
    throw new Error('Key is not valid')
  }

  if (!sodium.crypto_core_ed25519_is_valid_point(publicKey)) {
    throw new Error('Key not a valid ed25519 public key')
  }

  if (!name) {
    name = await userPrompt('\nChoose a name for this key pair: ')
  }

  await fsProm.mkdir(dir, { mode: USER_ONLY_RWX, recursive: true })

  const keyPath = path.resolve(path.format({ dir, name, ext: '.public' }))

  if (fs.existsSync(keyPath)) {
    console.log(`Public key already added as ${keyPath}`)
    console.log()
    console.log('Public key is', fs.readFileSync(keyPath, 'utf8'))
    return
  }

  await fsProm.writeFile(keyPath, pubkey, { mode: USER_ONLY_RW })

  console.log(`Public key saved as ${keyPath}`)
  console.log()
  console.log('Public key is', z32.encode(publicKey))
}
