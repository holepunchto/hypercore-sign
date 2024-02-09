const fsProm = require('fs/promises')
const path = require('path')
const test = require('brittle')
const Hypercore = require('hypercore')
const RAM = require('random-access-memory')
const { generate } = require('hypercore-signing-request')
const { spawn } = require('child_process')
const tmp = require('test-tmp')
const z32 = require('z32')

const DEBUG_LOG = false

async function getSignignRequest (t) {
  const core = new Hypercore(RAM.reusable(), { compat: false })
  t.teardown(async () => { await core.close() })

  await core.append('Block 0')
  await core.append('Block 1')

  const request = await generate(core)
  return z32.encode(request)
}

test('Basic flow: create keys, sign a core and verify it', async t => {
  const signRequest = await getSignignRequest(t)
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
      const data = bufferData.toString()

      if (DEBUG_LOG) console.log('[generate-keys]', data.toString())

      if (data.includes('Public key is')) {
        tCreateKeys.pass('Key creation done')
        publicKey = data.split('Public key is ')[1].trim()
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
    path.join(keysDir, 'public-key'), 'utf-8'
  )
  t.alike(
    publicKey,
    readPublicKey,
    'Public key got written to file'
  )

  const tSign = t.test()
  tSign.plan(2)

  const signProcess = spawn(
    'node', ['sign.js', signRequest], { env }
  )
  signProcess.on('close', (code) => {
    tSign.is(code, 0, '0 status code for message signing process')
  })

  let verifyParams = null
  try {
    signProcess.stdout.on('data', (bufferData) => {
      const data = bufferData.toString()
      if (DEBUG_LOG) console.log('[sign]', data)

      if (data.includes('hypercore-verify')) {
        verifyParams = data.split('hypercore-verify ')[1].trim().split(' ')
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
    'node', ['verify.js', ...verifyParams], { env }
  )
  verifyProcess.on('close', (code) => {
    tVerify.is(code, 0, '0 status code for verify process')
  })

  try {
    verifyProcess.stdout.on('data', (bufferData) => {
      const data = bufferData.toString()
      if (DEBUG_LOG) console.log('[verify]', data)

      if (data.includes('Signed by public key')) {
        if (data.includes(publicKey)) {
          tVerify.pass('Verified that the message got signed by the correct public key')
        } else {
          tVerify.fail('Message was signed by an incorrect public key--bug in test setup')
        }
      }
    })

    verifyProcess.stderr.on('data', (data) => {
      console.error(data.toString())
      t.fail('verify errored')
    })

    await tVerify
  } finally {
    // To ensure the process is always killed
    verifyProcess.kill('SIGKILL')
  }
})
