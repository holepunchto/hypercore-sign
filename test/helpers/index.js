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
  dummyVerifier,
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

async function dummyUser(
  proc,
  { name = '', password = 'password', confirmPassword = password } = {}
) {
  let publicKey
  await reader(proc, (output, onchange) => {
    if (output.includes('choose a name')) {
      proc.stdin.write(name + '\n')
      onchange()
    }

    if (output.includes('confirm password')) {
      proc.stdin.write(confirmPassword)
      onchange()
    } else if (output.includes('password:')) {
      proc.stdin.write(password)
      onchange()
    }

    if (output.includes('public key is')) {
      publicKey = output.split('public key is ')[1].trim()
      onchange()
    }
  })
  return publicKey
}

async function dummySigner(proc, { password = 'password', confirms = true, migrate = true } = {}) {
  const result = {
    migrated: false,
    response: null,
    isHyperdrive: false
  }

  await reader(proc, (output, onchange) => {
    if (output.includes('confirm?') || output.includes('answer with')) {
      const ans = Array.isArray(confirms) ? confirms.shift() : confirms ? 'y' : 'n'
      proc.stdin.write(ans + '\n')
      onchange()
    }

    if (output.includes('password:')) {
      proc.stdin.write(password)
      onchange()
    }

    if (output.includes('signing request')) {
      result.isHyperdrive = output.includes('hyperdrive')
      onchange()
    }

    if (output.includes('upgrade')) {
      proc.stdin.write(migrate ? 'y\n' : 'N\n')
      onchange()
    }

    if (output.includes('migrated')) {
      result.migrated = true
      onchange()
    }

    if (output.includes('reply with:')) {
      result.response = output.split('reply with:')[1].trim()
      onchange()
    }
  })

  return result
}

async function dummyVerifier(proc, { publicKey } = {}) {
  const result = {
    success: false,
    matched: false
  }

  await reader(proc, (output, onchange) => {
    if (publicKey && output.includes('signed')) {
      onchange()
      result.matched = output.includes(publicKey)
    }

    if (output.includes('signature verified.')) {
      onchange()
      result.success = true
    }
  })

  return result
}

async function reader(proc, ondata) {
  let marked = false
  let output = ''

  return new Promise((resolve, reject) => {
    proc.on('close', (code) => {
      if (code) reject('bad exit code')
      else resolve()
    })

    proc.stderr.on('data', (data) => {
      reject(new Error('process errored'))
    })

    proc.stdout.on('data', (data) => {
      output += data.toString().toLowerCase()
      ondata(output, mark)
      flush()
    })
  })

  function mark() {
    marked = true
  }

  function flush() {
    if (!marked) return
    output = ''
    marked = false
  }
}
