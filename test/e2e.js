const fsProm = require('fs/promises')
const path = require('path')
const test = require('brittle')
const Hypercore = require('hypercore')
const Hyperdrive = require('hyperdrive')
const Corestore = require('corestore')
const RAM = require('random-access-memory')
const { generate } = require('hypercore-signing-request')
const { spawn } = require('child_process')
const tmp = require('test-tmp')
const b4a = require('b4a')
const z32 = require('z32')
const c = require('compact-encoding')

const { Response } = require('../lib/messages')

const DEBUG_LOG = false
const DUMMY_PASSWORD = Math.random().toString().slice(2).padStart(8, 'x')

async function getSigningRequest (z32publicKey, t) {
  const namespace = b4a.alloc(32, 1)
  const publicKey = z32.decode(z32publicKey)

  const core = new Hypercore(RAM.reusable(), {
    compat: false,
    manifest: {
      version: 1,
      quorum: 1,
      signers: [{ publicKey, namespace }]
    }
  })

  t.teardown(async () => { await core.close() })

  await core.ready()

  const batch = core.batch()
  await batch.ready()

  await batch.append('Block 0')
  await batch.append('Block 1')
  await batch.flush({ keyPair: null })

  const request = await generate(batch)
  return {
    request: z32.encode(request),
    verify (signature) {
      const b = batch.createTreeBatch()
      return core.core.tree.crypto.verify(b.signable(batch.key), signature, publicKey)
    }
  }
}

async function getDriveSigningRequest (z32publicKey, t) {
  const publicKey = z32.decode(z32publicKey)

  const store = new Corestore(RAM.reusable(), { manifestVersion: 1, compat: false })
  const drive = new Hyperdrive(store)

  t.teardown(async () => {
    await drive.close()
    await store.close()
  })

  await drive.ready()

  await drive.put('a', b4a.from('Block 0'))
  await drive.put('b', b4a.from('Block 1'))

  const metadataSigners = drive.core.manifest.signers.slice()
  metadataSigners[0].publicKey = publicKey

  const metadataManifest = { ...drive.core.manifest, signers: metadataSigners }

  const metadataKey = Hypercore.key(metadataManifest)
  const contentKey = Hyperdrive.getContentKey(metadataManifest)

  const request = await generate(drive, { manifest: metadataManifest })

  return {
    request: z32.encode(request),
    verify ([metadata, content]) {
      const b1 = drive.core.createTreeBatch()
      const b2 = drive.blobs.core.createTreeBatch()

      return drive.core.core.tree.crypto.verify(b1.signable(metadataKey), metadata, publicKey) &&
        drive.core.core.tree.crypto.verify(b2.signable(contentKey), content, publicKey)
    }
  }
}

test('e2e - sign a core', async t => {
  const keysDir = await tmp(t)

  const tCreateKeys = t.test()
  tCreateKeys.plan(2)

  const env = {
    ...process.env, HYPERCORE_SIGN_KEYS_DIRECTORY: keysDir
  }

  const genKeysProcess = spawn(
    'node', ['generate-keys.js'], { env }
  )
  genKeysProcess.on('close', (code) => {
    tCreateKeys.is(code, 0, 'Successfully created keys')
  })

  let publicKey = null
  try {
    genKeysProcess.stdout.on('data', (bufferData) => {
      const data = bufferData.toString().toLowerCase()

      if (DEBUG_LOG) console.log('[generate-keys]', data.toString())

      if (data.includes('password:')) {
        // Enter the password
        genKeysProcess.stdin.write(DUMMY_PASSWORD)
      }
      if (data.includes('public key is')) {
        tCreateKeys.pass('Key creation done')
        publicKey = data.split('public key is ')[1].trim()
      }
    })

    genKeysProcess.stderr.on('data', (data) => {
      console.error(data.toString())
      t.fail('generate-keys errored')
    })

    await tCreateKeys
  } finally {
    // To ensure the process is always killed
    genKeysProcess.kill('SIGKILL')
  }

  const readPublicKey = await fsProm.readFile(
    path.join(keysDir, 'default.public'), 'utf-8'
  )
  t.alike(
    publicKey,
    readPublicKey,
    'Public key got written to file'
  )

  const { request, verify } = await getSigningRequest(publicKey, t)

  const tSign = t.test()
  tSign.plan(2)

  const signProcess = spawn(
    'node', ['sign.js', request], { env }
  )
  signProcess.on('close', (code) => {
    tSign.is(code, 0, '0 status code for message signing process')
  })

  let response = null
  try {
    signProcess.stdout.on('data', (bufferData) => {
      const data = bufferData.toString().toLowerCase()
      if (DEBUG_LOG) console.log('[sign]', data)

      if (data.includes('confirm?')) {
        // Enter the password
        signProcess.stdin.write('y\n')
      }

      if (data.includes('password')) {
        // Enter the password
        signProcess.stdin.write(DUMMY_PASSWORD)
      }

      if (data.includes('reply with:')) {
        response = data.split('reply with:')[1].trim()
        tSign.pass('Successfully signed the message')
      }
    })

    signProcess.stderr.on('data', (data) => {
      console.error(data.toString())
      t.fail('sign errored')
    })

    await tSign
  } finally {
    // To ensure the process is always killed
    signProcess.kill('SIGKILL')
  }

  const tVerify = t.test()
  tVerify.plan(2)

  const verifyProcess = spawn(
    'node', ['verify.js', response, request, publicKey], { env }
  )
  verifyProcess.on('close', (code) => {
    tVerify.is(code, 0, '0 status code for verify process')
  })

  try {
    let data = ''
    verifyProcess.stdout.on('data', (bufferData) => {
      data += bufferData.toString()
    })

    verifyProcess.stderr.on('data', (data) => {
      console.error(data.toString())
      t.fail('verify errored')
    })

    verifyProcess.stdout.on('close', () => {
      if (DEBUG_LOG) console.log('[verify]', data)

      if (data.includes('Signature verified.')) {
        if (data.includes(publicKey)) {
          tVerify.pass('Verified that the message got signed by the correct public key')
        } else {
          tVerify.fail('Message was signed by an incorrect public key--bug in test setup')
        }
      }
    })

    await tVerify

    // verify against actual core
    const { signatures } = c.decode(Response, z32.decode(response))
    t.ok(verify(signatures[0]))

    // sanity check
    signatures[0].fill(0)
    t.absent(verify(signatures[0]))
  } finally {
    // To ensure the process is always killed
    verifyProcess.kill('SIGKILL')
  }
})

test('e2e - sign a drive', async t => {
  const keysDir = await tmp(t)

  const tCreateKeys = t.test()
  tCreateKeys.plan(2)

  const env = {
    ...process.env, HYPERCORE_SIGN_KEYS_DIRECTORY: keysDir
  }

  const genKeysProcess = spawn(
    'node', ['generate-keys.js'], { env }
  )
  genKeysProcess.on('close', (code) => {
    tCreateKeys.is(code, 0, 'Successfully created keys')
  })

  let publicKey = null
  try {
    genKeysProcess.stdout.on('data', (bufferData) => {
      const data = bufferData.toString().toLowerCase()

      if (DEBUG_LOG) console.log('[generate-keys]', data.toString())

      if (data.includes('password:')) {
        // Enter the password
        genKeysProcess.stdin.write(DUMMY_PASSWORD)
      }
      if (data.includes('public key is')) {
        tCreateKeys.pass('Key creation done')
        publicKey = data.split('public key is ')[1].trim()
      }
    })

    genKeysProcess.stderr.on('data', (data) => {
      console.error(data.toString())
      t.fail('generate-keys errored')
    })

    await tCreateKeys
  } finally {
    // To ensure the process is always killed
    genKeysProcess.kill('SIGKILL')
  }

  const readPublicKey = await fsProm.readFile(
    path.join(keysDir, 'default.public'), 'utf-8'
  )
  t.alike(
    publicKey,
    readPublicKey,
    'Public key got written to file'
  )

  const { request, verify } = await getDriveSigningRequest(publicKey, t)

  const tSign = t.test()
  tSign.plan(2)

  const signProcess = spawn(
    'node', ['sign.js', request], { env }
  )
  signProcess.on('close', (code) => {
    tSign.is(code, 0, '0 status code for message signing process')
  })

  let response = null
  try {
    signProcess.stdout.on('data', (bufferData) => {
      const data = bufferData.toString().toLowerCase()
      if (DEBUG_LOG) console.log('[sign]', data)

      if (data.includes('confirm?')) {
        // Enter the password
        signProcess.stdin.write('y\n')
      }

      if (data.includes('password')) {
        // Enter the password
        signProcess.stdin.write(DUMMY_PASSWORD)
      }

      if (data.includes('reply with:')) {
        response = data.split('reply with:')[1].trim()
        tSign.pass('Successfully signed the message')
      }
    })

    signProcess.stderr.on('data', (data) => {
      console.error(data.toString())
      t.fail('sign errored')
    })

    await tSign
  } finally {
    // To ensure the process is always killed
    signProcess.kill('SIGKILL')
  }

  const tVerify = t.test()
  tVerify.plan(2)

  const verifyProcess = spawn(
    'node', ['verify.js', response, request, publicKey], { env }
  )
  verifyProcess.on('close', (code) => {
    tVerify.is(code, 0, '0 status code for verify process')
  })

  try {
    let data = ''
    verifyProcess.stdout.on('data', (bufferData) => {
      data += bufferData.toString()
    })

    verifyProcess.stderr.on('data', (data) => {
      console.error(data.toString())
      t.fail('verify errored')
    })

    verifyProcess.stdout.on('close', () => {
      if (DEBUG_LOG) console.log('[verify]', data)

      if (data.includes('Signature verified.')) {
        if (data.includes(publicKey)) {
          tVerify.pass('Verified that the message got signed by the correct public key')
        } else {
          tVerify.fail('Message was signed by an incorrect public key--bug in test setup')
        }
      }
    })

    await tVerify

    // verify against actual core
    const { signatures } = c.decode(Response, z32.decode(response))
    t.ok(verify(signatures))

    // sanity check
    signatures[0].fill(0)
    t.absent(verify(signatures))
  } finally {
    // To ensure the process is always killed
    verifyProcess.kill('SIGKILL')
  }
})
