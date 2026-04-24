const fs = require('fs/promises')
const path = require('path')
const test = require('brittle')
const tmpDir = require('test-tmp')
const Hypercore = require('hypercore')
const crypto = require('hypercore-crypto')
const Hyperdrive = require('hyperdrive')
const Corestore = require('corestore')
const { getKeyInfo } = require('hypercore-sign-lib')
const { generate, decodeResponse } = require('hypercore-signing-request')
const { spawn } = require('child_process')
const b4a = require('b4a')
const z32 = require('z32')

const DEBUG_LOG = process.env.DEBUG_LOG === '1'
const DUMMY_PASSWORD = Math.random().toString().slice(2).padStart(8, 'x')

test('e2e - sign a core', async (t) => {
  const keysDir = await t.tmp()

  const tCreateKeys = t.test()
  tCreateKeys.plan(2)

  const env = {
    ...process.env,
    HYPERCORE_SIGN_KEYS_DIRECTORY: keysDir
  }

  const genKeysProcess = spawn('node', ['generate-keys.js'], { env })
  genKeysProcess.on('close', (code) => {
    tCreateKeys.is(code, 0, 'Successfully created keys')
  })

  let publicKey = null
  try {
    let data = ''

    genKeysProcess.stdout.on('data', (bufferData) => {
      data += bufferData.toString().toLowerCase()
      if (DEBUG_LOG) console.log('[generate-keys]', bufferData.toString().toLowerCase())

      data = drainPrompts(data, [
        {
          text: 'keypair password:',
          action() {
            genKeysProcess.stdin.write(DUMMY_PASSWORD + '\n')
          }
        },
        {
          text: 'confirm password:',
          action() {
            genKeysProcess.stdin.write(DUMMY_PASSWORD + '\n')
          }
        }
      ])

      if (publicKey === null && data.includes('public key is ')) {
        tCreateKeys.pass('Key creation done')
        publicKey = data.split('public key is ')[1].split('\n')[0].trim()
        data = sliceData(data, 'public key is ')
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

  const readPublicKey = await fs.readFile(path.join(keysDir, 'default.public'), 'utf-8')
  t.alike(publicKey, readPublicKey, 'Public key got written to file')

  const { request, verify } = await getSigningRequest(publicKey, t)

  const tSign = t.test()
  tSign.plan(2)

  const signProcess = spawn('node', ['sign.js', request], { env })
  signProcess.on('close', (code) => {
    tSign.is(code, 0, '0 status code for message signing process')
  })

  let response = null
  try {
    let data = ''

    signProcess.stdout.on('data', (bufferData) => {
      data += bufferData.toString().toLowerCase()
      if (DEBUG_LOG) console.log('[sign]', bufferData.toString().toLowerCase())

      data = drainPrompts(data, [
        {
          text: 'confirm?',
          action() {
            signProcess.stdin.write('y\n')
          }
        },
        {
          text: 'keypair password:',
          action() {
            signProcess.stdin.write(DUMMY_PASSWORD + '\n')
          }
        }
      ])

      if (response === null && data.includes('reply with:')) {
        response = data.split('reply with:\n\n')[1].split('\n')[0].trim()
        tSign.pass('Successfully signed the message')
        data = sliceData(data, 'reply with:')
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

  const verifyProcess = spawn('node', ['verify.js', response, request, publicKey], { env })
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
    const { signatures } = decodeResponse(z32.decode(response))
    t.ok(verify(signatures[0]))

    // sanity check
    signatures[0].fill(0)
    t.absent(verify(signatures[0]))
  } finally {
    // To ensure the process is always killed
    verifyProcess.kill('SIGKILL')
  }
})

test('e2e - sign a drive', async (t) => {
  const keysDir = await t.tmp()

  const tCreateKeys = t.test()
  tCreateKeys.plan(2)

  const env = {
    ...process.env,
    HYPERCORE_SIGN_KEYS_DIRECTORY: keysDir
  }

  const genKeysProcess = spawn('node', ['generate-keys.js'], { env })
  genKeysProcess.on('close', (code) => {
    tCreateKeys.is(code, 0, 'Successfully created keys')
  })

  let publicKey = null
  try {
    let data = ''

    genKeysProcess.stdout.on('data', (bufferData) => {
      data += bufferData.toString().toLowerCase()
      if (DEBUG_LOG) console.log('[generate-keys]', bufferData.toString())

      data = drainPrompts(data, [
        {
          text: 'keypair password:',
          action() {
            genKeysProcess.stdin.write(DUMMY_PASSWORD + '\n')
          }
        },
        {
          text: 'confirm password:',
          action() {
            genKeysProcess.stdin.write(DUMMY_PASSWORD + '\n')
          }
        }
      ])

      if (publicKey === null && data.includes('public key is ')) {
        tCreateKeys.pass('Key creation done')
        publicKey = data.split('public key is ')[1].split('\n')[0].trim()
        data = sliceData(data, 'public key is ')
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

  const readPublicKey = await fs.readFile(path.join(keysDir, 'default.public'), 'utf-8')
  t.alike(publicKey, readPublicKey, 'Public key got written to file')

  const { request, verify } = await getDriveSigningRequest(publicKey, t)

  const tSign = t.test()
  tSign.plan(2)

  const signProcess = spawn('node', ['sign.js', request], { env })
  signProcess.on('close', (code) => {
    tSign.is(code, 0, '0 status code for message signing process')
  })

  let response = null
  try {
    let data = ''

    signProcess.stdout.on('data', (bufferData) => {
      data += bufferData.toString().toLowerCase()
      if (DEBUG_LOG) console.log('[sign]', bufferData.toString().toLowerCase())

      data = drainPrompts(data, [
        {
          text: 'confirm?',
          action() {
            signProcess.stdin.write('y\n')
          }
        },
        {
          text: 'keypair password:',
          action() {
            signProcess.stdin.write(DUMMY_PASSWORD + '\n')
          }
        }
      ])

      if (response === null && data.includes('reply with:')) {
        response = data.split('reply with:\n\n')[1].split('\n')[0].trim()
        tSign.pass('Successfully signed the message')
        data = sliceData(data, 'reply with:')
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

  const verifyProcess = spawn('node', ['verify.js', response, request, publicKey], { env })
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
    const { signatures } = decodeResponse(z32.decode(response))
    t.ok(verify(signatures))

    // sanity check
    signatures[0].fill(0)
    t.absent(verify(signatures))
  } finally {
    // To ensure the process is always killed
    verifyProcess.kill('SIGKILL')
  }
})

test('e2e - v1 fixture', async (t) => {
  t.plan(3)

  const request = await fs.readFile(
    path.join(__dirname, 'fixtures', 'requests', 'v1.request'),
    'utf8'
  )
  const env = {
    ...process.env,
    HYPERCORE_SIGN_KEYS_DIRECTORY: path.join(__dirname, 'fixtures', 'keys')
  }

  const proc = spawn('node', ['sign.js', request], { env })

  t.teardown(() => proc.kill('SIGKILL'))

  proc.on('close', (code) => {
    t.is(code, 0, '0 status code for message signing process')
  })

  let data = ''

  proc.stdout.on('data', (bufferData) => {
    data += bufferData.toString().toLowerCase()
    if (DEBUG_LOG) console.log('[sign]', bufferData.toString().toLowerCase())

    if (data.includes('signing request')) {
      t.ok(data.includes('hypercore'))
      data = sliceData(data, 'signing request')
    }

    data = drainPrompts(data, [
      {
        text: 'confirm?',
        action() {
          proc.stdin.write('y\n')
        }
      },
      {
        text: 'keypair password:',
        action() {
          proc.stdin.write('password\n')
        }
      }
    ])

    if (data.includes('reply with:')) {
      t.pass('Successfully signed the message')
      data = sliceData(data, 'reply with:')
    }
  })

  proc.stderr.on('data', (data) => {
    console.error(data.toString())
    t.fail('sign errored')
  })
})

test('e2e - v2 fixture', async (t) => {
  t.plan(3)

  const request = await fs.readFile(
    path.join(__dirname, 'fixtures', 'requests', 'v2.request'),
    'utf8'
  )
  const env = {
    ...process.env,
    HYPERCORE_SIGN_KEYS_DIRECTORY: path.join(__dirname, 'fixtures', 'keys')
  }

  const proc = spawn('node', ['sign.js', request], { env })

  t.teardown(() => proc.kill('SIGKILL'))

  proc.on('close', (code) => {
    t.is(code, 0, '0 status code for message signing process')
  })

  let data = ''

  proc.stdout.on('data', (bufferData) => {
    data += bufferData.toString().toLowerCase()
    if (DEBUG_LOG) console.log('[sign]', bufferData.toString().toLowerCase())

    if (data.includes('signing request')) {
      t.ok(data.includes('hypercore'))
      data = sliceData(data, 'signing request')
    }

    data = drainPrompts(data, [
      {
        text: 'confirm?',
        action() {
          proc.stdin.write('y\n')
        }
      },
      {
        text: 'keypair password:',
        action() {
          proc.stdin.write('password\n')
        }
      }
    ])

    if (data.includes('reply with:')) {
      t.pass('Successfully signed the message')
      data = sliceData(data, 'reply with:')
    }
  })

  proc.stderr.on('data', (data) => {
    console.error(data.toString())
    t.fail('sign errored')
  })
})

test('e2e - v2 drive fixture', async (t) => {
  t.plan(3)

  const request = await fs.readFile(
    path.join(__dirname, 'fixtures', 'requests', 'v2-drive.request'),
    'utf8'
  )
  const env = {
    ...process.env,
    HYPERCORE_SIGN_KEYS_DIRECTORY: path.join(__dirname, 'fixtures', 'keys')
  }

  const proc = spawn('node', ['sign.js', request], { env })

  t.teardown(() => proc.kill('SIGKILL'))

  proc.on('close', (code) => {
    t.is(code, 0, '0 status code for message signing process')
  })

  let data = ''

  proc.stdout.on('data', (bufferData) => {
    data += bufferData.toString().toLowerCase()
    if (DEBUG_LOG) console.log('[sign]', bufferData.toString().toLowerCase())

    // Check request
    if (data.includes('signing request')) {
      t.ok(data.includes('hyperdrive'))
      data = sliceData(data, 'signing request')
    }

    data = drainPrompts(data, [
      {
        text: 'confirm?',
        action() {
          proc.stdin.write('y\n')
        }
      },
      {
        text: 'keypair password:',
        action() {
          proc.stdin.write('password\n')
        }
      }
    ])

    // Verify output
    if (data.includes('reply with:')) {
      t.pass('Successfully signed the message')
      data = sliceData(data, 'reply with:')
    }
  })

  proc.stderr.on('data', (data) => {
    console.error(data.toString())
    t.fail('sign errored')
  })
})

test('e2e - migrate legacy keys', async (t) => {
  t.plan(6)

  const dir = await tmpDir(t)

  const request = await fs.readFile(
    path.join(__dirname, 'fixtures', 'requests', 'v2-drive.request'),
    'utf8'
  )

  await fs.cp(
    path.join(__dirname, 'fixtures', 'keys', 'default.v0'),
    path.join(dir, 'keys', 'default')
  )
  await fs.cp(
    path.join(__dirname, 'fixtures', 'keys', 'default.public'),
    path.join(dir, 'keys', 'default.public')
  )

  const env = {
    ...process.env,
    HYPERCORE_SIGN_KEYS_DIRECTORY: path.join(dir, 'keys')
  }

  const legacyKey = await fs.readFile(path.join(dir, 'keys', 'default'), 'utf8')
  const legacyInfo = getKeyInfo(z32.decode(legacyKey))

  t.is(legacyInfo.version, 0)

  const proc = spawn('node', ['sign.js', request], { env })

  t.teardown(() => proc.kill('SIGKILL'))

  let ondone = null
  const done = new Promise((resolve) => (ondone = resolve))

  proc.on('close', (code) => {
    t.is(code, 0, '0 status code for message signing process')
    ondone()
  })

  let data = ''

  proc.stdout.on('data', (bufferData) => {
    data += bufferData.toString().toLowerCase()
    if (DEBUG_LOG) console.log('[sign]', bufferData.toString().toLowerCase())

    data = drainPrompts(data, [
      {
        text: 'would you like to upgrade?',
        action() {
          t.pass()
          proc.stdin.write('y\n')
        }
      },
      {
        text: 'confirm?',
        action() {
          proc.stdin.write('y\n')
        }
      },
      {
        text: 'keypair password:',
        action() {
          proc.stdin.write('password\n')
        }
      }
    ])

    if (data.includes('reply with:')) {
      t.fail()
    }
  })

  proc.stderr.on('data', (data) => {
    console.error(data.toString())
    t.fail('sign errored')
  })

  await done

  const key = await fs.readFile(path.join(dir, 'keys', 'default'), 'utf8')
  const info = getKeyInfo(z32.decode(key))

  t.is(info.version, 1)

  const backupKey = await fs.readFile(path.join(dir, 'keys', 'default.v3.backup'), 'utf8')
  t.is(backupKey, legacyKey, 'backup is same as original key')
  t.not(backupKey, key, 'backup is different from migrated key')
})

test('e2e - do not migrate legacy keys', async (t) => {
  t.plan(7)

  const dir = await tmpDir(t)

  const request = await fs.readFile(
    path.join(__dirname, 'fixtures', 'requests', 'v2-drive.request'),
    'utf8'
  )

  await fs.cp(
    path.join(__dirname, 'fixtures', 'keys', 'default.v0'),
    path.join(dir, 'keys', 'default')
  )
  await fs.cp(
    path.join(__dirname, 'fixtures', 'keys', 'default.public'),
    path.join(dir, 'keys', 'default.public')
  )

  const env = {
    ...process.env,
    HYPERCORE_SIGN_KEYS_DIRECTORY: path.join(dir, 'keys')
  }

  const legacyKey = await fs.readFile(path.join(dir, 'keys', 'default'), 'utf8')
  const legacyInfo = getKeyInfo(z32.decode(legacyKey))

  t.is(legacyInfo.version, 0)

  const proc = spawn('node', ['sign.js', request], { env })

  t.teardown(() => proc.kill('SIGKILL'))

  let ondone = null
  const done = new Promise((resolve) => (ondone = resolve))

  proc.on('close', (code) => {
    t.is(code, 0, '0 status code for message signing process')
    ondone()
  })

  let data = ''

  proc.stdout.on('data', (bufferData) => {
    data += bufferData.toString().toLowerCase()
    if (DEBUG_LOG) console.log('[sign]', bufferData.toString().toLowerCase())

    data = drainPrompts(data, [
      {
        text: 'would you like to upgrade?',
        action() {
          t.pass()
          proc.stdin.write('N\n')
        }
      },
      {
        text: 'confirm?',
        action() {
          proc.stdin.write('y\n')
        }
      },
      {
        text: 'keypair password:',
        action() {
          proc.stdin.write('password\n')
        }
      }
    ])

    if (data.includes('reply with:')) {
      t.pass()
      data = sliceData(data, 'reply with:')
    }
  })

  proc.stderr.on('data', (data) => {
    console.error(data.toString())
    t.fail('sign errored')
  })

  await done

  const key = await fs.readFile(path.join(dir, 'keys', 'default'), 'utf8')
  const info = getKeyInfo(z32.decode(key))

  t.is(info.version, 0)

  await t.exception(fs.stat(path.join(dir, 'keys', 'default.v3.backup')), 'backup does not exist')
  t.alike(legacyKey, key, 'key did not change')
})

async function getSigningRequest(z32publicKey, t) {
  const namespace = b4a.alloc(32, 1)
  const publicKey = z32.decode(z32publicKey)

  const src = new Hypercore(await t.tmp())

  const core = new Hypercore(await t.tmp(), {
    compat: false,
    manifest: {
      version: 1,
      quorum: 1,
      signers: [{ publicKey, namespace }]
    }
  })

  t.teardown(async () => {
    await core.close()
    await src.close()
  })

  await core.ready()
  await src.ready()

  await src.append('Block 0')
  await src.append('Block 1')

  const request = await generate(src, { manifest: core.manifest })

  return {
    request: z32.encode(request),
    verify(signature) {
      const b = src.state.createTreeBatch()
      return crypto.verify(b.signable(core.key), signature, publicKey)
    }
  }
}

async function getDriveSigningRequest(z32publicKey, t) {
  const publicKey = z32.decode(z32publicKey)

  const store = new Corestore(await t.tmp(), {
    manifestVersion: 1,
    compat: false
  })
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
    verify([metadata, content]) {
      const b1 = drive.core.state.createTreeBatch()
      const b2 = drive.blobs.core.state.createTreeBatch()

      return (
        crypto.verify(b1.signable(metadataKey), metadata, publicKey) &&
        crypto.verify(b2.signable(contentKey), content, publicKey)
      )
    }
  }
}

function sliceData(data, text) {
  const index = data.indexOf(text)
  if (index === -1) return data

  const sliced = data.slice(index + text.length)
  if (DEBUG_LOG) console.log('<slice-before>', data, '<slice-start>', sliced, '<slice-end>')
  return sliced
}

function drainPrompts(data, prompts) {
  while (true) {
    const prompt = nextPrompt(data, prompts)
    if (prompt === null) return data

    data = sliceData(data, prompt.text)
    prompt.action()
  }
}

function nextPrompt(data, prompts) {
  let next = null

  for (const prompt of prompts) {
    const index = data.indexOf(prompt.text)
    if (index === -1) continue
    if (next !== null && next.index <= index) continue

    next = { index, ...prompt }
  }

  return next
}
