const Hypercore = require('hypercore')
const Hyperdrive = require('hyperdrive')
const Corestore = require('corestore')
const crypto = require('hypercore-crypto')
const { generate } = require('hypercore-signing-request')
const z32 = require('z32')
const b4a = require('b4a')

module.exports = {
  dummyUser,
  dummySigner,
  getSigningRequest,
  getDriveSigningRequest
}

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

function dummyUser(proc, { name = '', password = 'password', confirmPassword = password } = {}) {
  return new Promise((resolve, reject) => {
    proc.on('close', () => resolve(null))

    proc.stderr.on('data', (data) => {
      reject(new Error('Key generation failed'))
    })

    proc.stdout.on('data', (bufferData) => {
      const data = bufferData.toString().toLowerCase()

      if (data.includes('choose a name')) {
        proc.stdin.write(name + '\n')
      } else if (data.includes('confirm password')) {
        proc.stdin.write(confirmPassword)
      } else if (data.includes('password:')) {
        proc.stdin.write(password)
      } else if (data.includes('public key is')) {
        resolve(data.split('public key is ')[1].trim())
      }
    })
  })
}

function dummySigner(proc, { password = 'password', confirms = true } = {}) {
  return new Promise((resolve, reject) => {
    proc.on('close', () => resolve(null))

    proc.stderr.on('data', (data) => {
      reject(new Error('Signature generation failed'))
    })

    proc.stdout.on('data', (bufferData) => {
      const data = bufferData.toString().toLowerCase()

      if (data.includes('confirm?') || data.includes('answer with')) {
        const ans = Array.isArray(confirms) ? confirms.shift() : confirms ? 'y' : 'n'
        proc.stdin.write(ans + '\n')
      } else if (data.includes('password:')) {
        proc.stdin.write(password)
      } else if (data.includes('reply with:')) {
        resolve(data.split('reply with:')[1].trim())
      }
    })
  })
}
