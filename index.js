const path = require('path')
const fs = require('fs')
const fsProm = require('fs/promises')
const hypercoreRequest = require('hypercore-signing-request')
const crypto = require('hypercore-crypto')
const z32 = require('z32')
const sodium = require('sodium-native')

const { generateKeys, sign, verify, getKeyInfo } = require('hypercore-sign-lib')

const { readPassword, confirmPassword } = require('./lib/password')
const { migrateV3 } = require('./migrations/v3')

const {
  userPrompt,
  userConfirm,
  formatHypercoreRequest,
  formatHyperdriveRequest
} = require('./lib/utils')

const { bold, dim, cyan, yellow, green, red, gray, box, field } = require('./lib/formatting')

// fs permissions
const USER_ONLY_R = 0o400
const USER_ONLY_RW = 0o600
const USER_ONLY_RWX = 0o700

const V3_KEY_VERSION = 0 // legacy key version

module.exports = {
  generator,
  signer,
  verifier,
  add
}

async function generator(dir) {
  const name = await userPrompt('\nChoose a name for this key pair: (default) ', 'default')

  await fsProm.mkdir(dir, { mode: USER_ONLY_RWX, recursive: true })

  const secretKeyPath = path.resolve(path.format({ dir, name }))
  const publicKeyPath = path.resolve(path.format({ dir, name, ext: '.public' }))

  if (fs.existsSync(secretKeyPath)) {
    console.log(dim(`Secret key already written to ${secretKeyPath}`))
    console.log(dim(`Public key already written to ${publicKeyPath}`))
    console.log()
    console.log(gray('Public key is ') + cyan(fs.readFileSync(publicKeyPath, 'utf8')))
    return
  }

  console.log(yellow('Your secret key will be encrypted with a password.'))
  console.log('Please choose one now:\n')
  const password = await readPassword()

  if (!(await confirmPassword(password))) {
    console.error(red('Passwords do not match'))
    process.exit(1)
  }

  const { secretKey, publicKey } = await generateKeys(password)

  // Prompt a confirmation when overwriting
  // (Because you probably don't want to overwrite these,
  // once they have been generated)

  await fsProm.writeFile(secretKeyPath, z32.encode(secretKey), {
    mode: USER_ONLY_R
  })

  await fsProm.writeFile(publicKeyPath, z32.encode(publicKey), {
    mode: USER_ONLY_RW
  })

  console.log(green('\nSecret key written to ') + dim(secretKeyPath))
  console.log(green('Public key written to ') + dim(publicKeyPath))
  console.log()
  console.log(gray('Public key is ') + cyan(z32.encode(publicKey)))
}

async function signer(signingRequest, keyPath) {
  const secretKeyPath = path.resolve(path.format(keyPath))
  const publicKeyPath = path.resolve(path.format({ ...keyPath, ext: '.public' }))

  const secretKey = z32.decode(await fsProm.readFile(secretKeyPath, 'utf-8'))
  const publicKey = z32.decode(await fsProm.readFile(publicKeyPath, 'utf-8'))

  const info = getKeyInfo(secretKey)

  if (info.version === V3_KEY_VERSION) {
    console.log(yellow('Found legacy key at: ') + dim(secretKeyPath))

    if (await userConfirm('Would you like to upgrade? [y/N]')) {
      console.log(dim('Migrating keys...'))
      await migrateKeys(secretKey, publicKey, secretKeyPath)

      console.log(green('Keys migrated successfully.') + dim(' Please run your request again.'))
      process.exit(0)
    }
  }

  let request = null
  let req = null

  try {
    request = z32.decode(signingRequest)
    req = hypercoreRequest.decode(request)
  } catch (e) {
    throw new Error('\nCould not decode the signing request. Invalid signing request?')
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
    console.log(red('\nRequest aborted.'))
    process.exit(1)
  }

  console.log(green('\nRequest data is confirmed'))
  console.log(dim('Proceeding to sign...'))

  console.log(dim(`\nSigning with ${secretKeyPath}\n`))
  if (!(await userConfirm())) {
    console.error(red('\nRequest aborted.'))
    process.exit(1)
  }
  console.log()

  const password = await readPassword()
  const response = await sign(z32.decode(signingRequest), secretKey, password, publicKey)

  console.log(`\n${gray('Signed with public key:')}\n\n${cyan(z32.encode(publicKey))}`)
  console.log(`\n${bold('Reply with:')}\n\n${green(z32.encode(response))}`)
}

async function verifier(response, signingRequest, pubkey) {
  const res = hypercoreRequest.decodeResponse(z32.decode(response))

  let req = null
  try {
    req = hypercoreRequest.decode(z32.decode(signingRequest))
  } catch (e) {
    throw new Error('\nCould not decode the signing request. Invalid signing request?')
  }

  if (Buffer.compare(res.requestHash, crypto.hash(z32.decode(signingRequest))) !== 0) {
    throw new Error('Signature was not made over this request')
  }

  let known = null
  if (typeof pubkey !== 'string') {
    const keyPath =
      pubkey.name === ''
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
      known = getKnownPeerName(keyPath)
      pubkey = await fsProm.readFile(keyPath, 'utf8')
    } else if (stat.isDirectory()) {
      known = false

      const dir = await fsProm.readdir(keyPath)
      const check = z32.encode(res.publicKey)

      for (const file of dir) {
        const keyFile = path.join(keyPath, file)
        const peer = await fsProm.readFile(keyFile, 'utf8')
        if (peer === check) {
          known = getKnownPeerName(keyFile)
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

  // throws
  verify(z32.decode(response), z32.decode(signingRequest), z32.decode(pubkey))

  console.log(green('\nSignature verified.'))
  if (known) console.log(`\n${gray('Signed by known peer:')} ${cyan(`"${known}"`)}`)
  else console.log(`\n${cyan(pubkey)} ${dim('signed the following request:')}`)

  console.log(
    '\n' +
      [
        field('core', req.id),
        field('fork', req.fork),
        field('length', req.length),
        field('treeHash', req.treeHash.toString('hex'))
      ].join('\n')
  )
}

async function add(pubkey, dir, name) {
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
    console.log(yellow(`Public key already added as ${keyPath}`))
    console.log()
    console.log(gray('Public key is ') + cyan(fs.readFileSync(keyPath, 'utf8')))
    return
  }

  await fsProm.writeFile(keyPath, pubkey, { mode: USER_ONLY_RW })

  console.log(green('Public key saved as ') + dim(keyPath))
  console.log()
  console.log(gray('Public key is ') + cyan(z32.encode(publicKey)))
}

async function migrateKeys(secretKey, publicKey, secretKeyPath) {
  const migrated = await migrateV3(secretKey, publicKey)

  const backupSecretKey = backupPath(secretKeyPath, 'v3')

  let copied = false
  try {
    await fsProm.copyFile(secretKeyPath, backupSecretKey)
    copied = true

    console.log(dim('Writing new keys to: ' + secretKeyPath))

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
        console.log(red('Migration failed: please restore keys from: ' + backupSecretKey))
      }
    }

    throw new Error('Migration failed')
  }
}

function backupPath(filePath, version) {
  if (!version) throw new Error('Must specify version')
  return filePath + '.' + version + '.backup'
}

function getKnownPeerName(fileName) {
  return path.parse(fileName).name
}
