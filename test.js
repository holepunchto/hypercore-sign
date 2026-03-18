const b4a = require('b4a')
const test = require('brittle')
const cenc = require('compact-encoding')
const Corestore = require('corestore')
const crypto = require('hypercore-crypto')
const CoreRequest = require('hypercore-signing-request')
const createTestnet = require('hyperdht/testnet')
const Hyperdrive = require('hyperdrive')
const Hyperswarm = require('hyperswarm')
const sodium = require('sodium-native')
const z32 = require('z32')

const CoreSign = require('.')

test('generateKeys', async (t) => {
  const [keys] = setupSigners()
  t.ok(keys.id, 'should have id')
  t.ok(keys.publicKey, 'should have publicKey')
  t.ok(keys.secretKey, 'should have secretKey')
})

test('sign a core and verify', async (t) => {
  const signers = setupSigners()
  const { store } = await setupReplication(t)

  const request = await getSigningRequest(signers, store)
  const response = sign(request, signers[0])
  t.ok(response, 'should have response')
  CoreSign.verify(response, z32.encode(request), z32.encode(signers[0].publicKey))
  t.pass('should verify signing request')
})

test('sign a drive and verify', async (t) => {
  const signers = setupSigners()
  const { store } = await setupReplication(t)

  const request = await getDriveSigningRequest(signers, store)
  const response = sign(request, signers[0])
  t.ok(response, 'should have response')
  CoreSign.verify(response, z32.encode(request), z32.encode(signers[0].publicKey))
  t.pass('should verify drive signing request')
})

function sign(request, signer) {
  // clone to avoid mutation
  const clonedSigner = Object.keys(signer).reduce((acc, key) => {
    acc[key] = b4a.from(signer[key])
    return acc
  }, {})

  const decodedReq = CoreRequest.decode(request)
  const signables = CoreRequest.signable(clonedSigner.publicKey, decodedReq)

  const password = sodium.sodium_malloc(8)
  sodium.randombytes_buf_deterministic(password, clonedSigner.seed)

  const res = CoreSign.sign(request, clonedSigner.secretKey, password)

  return z32.encode(res)
}

async function getSigningRequest(signers, store) {
  const core = store.get({ name: 'test' })
  await core.ready()
  await core.append('Block 0')
  await core.append('Block 1')

  const namespace = b4a.alloc(32, 1)
  const manifest = {
    version: 1,
    hash: 'blake2b',
    quorum: 1,
    signers: signers.map(({ publicKey }) => ({
      signature: 'ed25519',
      publicKey,
      namespace
    }))
  }
  return CoreRequest.generate(core, { manifest })
}

async function getDriveSigningRequest(signers, store) {
  const drive = new Hyperdrive(store)
  await drive.ready()
  await drive.put('a', b4a.from('Block 0'))
  await drive.put('b', b4a.from('Block 1'))

  const manifest = {
    version: 1,
    hash: 'blake2b',
    quorum: 1,
    signers: signers.map(({ publicKey }) => ({
      signature: 'ed25519',
      publicKey,
      namespace: b4a.alloc(32, 1)
    }))
  }
  return CoreRequest.generateDrive(drive, { manifest })
}

function setupSigners(n = 1) {
  const signers = []
  for (let i = 0; i < n; i++) {
    const seed = sodium.sodium_malloc(sodium.randombytes_SEEDBYTES)
    sodium.randombytes_buf(seed)
    const password = sodium.sodium_malloc(8)
    sodium.randombytes_buf_deterministic(password, seed)

    const keys = CoreSign.generateKeys(password)
    signers.push({ ...keys, seed })
  }
  return signers
}

async function setupReplication(t, n = 1, network) {
  const res = network ?? (await setupTestnet(t))
  const { bootstrap } = res

  for (let step = 1; step <= n; step++) {
    const storage = await t.tmp()
    const store = new Corestore(storage)
    t.teardown(() => store.close(), { order: 4000 })
    const swarm = new Hyperswarm({ bootstrap })
    t.teardown(() => swarm.destroy(), { order: 3000 })

    swarm.on('connection', (conn) => store.replicate(conn))

    const nstring = step > 1 ? step : ''
    res[`storage${nstring}`] = storage
    res[`store${nstring}`] = store
    res[`swarm${nstring}`] = swarm
  }

  return res
}

async function setupTestnet(t) {
  const testnet = await createTestnet()
  t.teardown(() => testnet.destroy(), { order: 5000 })
  const bootstrap = testnet.bootstrap
  return { testnet, bootstrap }
}
