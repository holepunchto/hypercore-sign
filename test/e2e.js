const fs = require('fs/promises')
const path = require('path')
const test = require('brittle')
const { spawn } = require('child_process')
const z32 = require('z32')
const hypercoreRequest = require('hypercore-signing-request')
const { getKeyInfo } = require('hypercore-sign-lib')

const {
  dummyUser,
  dummySigner,
  dummyVerifier,
  getSigningRequest,
  getDriveSigningRequest
} = require('./helpers')

const DUMMY_PASSWORD = Math.random().toString().slice(2).padStart(8, 'x')

test('e2e - sign a core', async (t) => {
  const keysDir = await t.tmp()

  const t1 = t.test()
  t1.plan(2)

  const g = spawn('node', ['./bin/cli.js', 'generate', '-d', keysDir])

  t1.teardown(() => g.kill('SIGKILL'))

  g.on('close', (code) => {
    t1.is(code, 0, 'Successfully created keys')
  })

  const publicKey = await dummyUser(g, { password: DUMMY_PASSWORD })
  const exp = await fs.readFile(path.join(keysDir, 'default.public'), 'utf-8')

  t1.alike(publicKey, exp, 'Public key got written to file')
  await t1

  const { request, verify } = await getSigningRequest(publicKey, t)

  const keyFile = path.join(keysDir, 'default')

  const s = spawn('node', ['./bin/cli.js', 'sign', request, '-i', keyFile])
  const result = await dummySigner(s, { password: DUMMY_PASSWORD })

  t.ok(result.response)
  t.absent(result.isHyperdrive)

  const v = spawn('node', ['./bin/cli.js', 'verify', result.response, request, publicKey])
  const verified = await dummyVerifier(v, { publicKey })

  t.ok(verified.success)
  t.ok(verified.matched)

  // verify against actual core
  const { signatures } = hypercoreRequest.decodeResponse(z32.decode(result.response))
  t.ok(verify(signatures[0]))

  // sanity check
  signatures[0].fill(0)
  t.absent(verify(signatures[0]))
})

test('e2e - sign a drive', async (t) => {
  const keysDir = await t.tmp()

  const t1 = t.test()
  t1.plan(2)

  const g = spawn('node', ['./bin/cli.js', 'generate', '-d', keysDir])

  t1.teardown(() => g.kill('SIGKILL'))

  g.on('close', (code) => {
    t1.is(code, 0, 'Successfully created keys')
  })

  const publicKey = await dummyUser(g, { password: DUMMY_PASSWORD })
  const exp = await fs.readFile(path.join(keysDir, 'default.public'), 'utf-8')

  t1.alike(publicKey, exp, 'Public key got written to file')
  await t1

  const { request, verify } = await getDriveSigningRequest(publicKey, t)

  const keyFile = path.join(keysDir, 'default')

  const s = spawn('node', ['./bin/cli.js', 'sign', request, '-i', keyFile])
  const result = await dummySigner(s, { password: DUMMY_PASSWORD })

  t.ok(result.response)
  t.ok(result.isHyperdrive)

  const v = spawn('node', ['./bin/cli.js', 'verify', result.response, request, publicKey])
  const verified = await dummyVerifier(v, { publicKey })

  t.ok(verified.success)
  t.ok(verified.matched)

  // verify against actual core
  const { signatures } = hypercoreRequest.decodeResponse(z32.decode(result.response))
  t.ok(verify(signatures))

  // sanity check
  signatures[0].fill(0)
  t.absent(verify(signatures))
})

test('e2e - v1 fixture', async (t) => {
  const request = await fs.readFile(
    path.join(__dirname, 'fixtures', 'requests', 'default.v1.core'),
    'utf8'
  )
  const response = await fs.readFile(
    path.join(__dirname, 'fixtures', 'responses', 'default.v1.core'),
    'utf8'
  )

  const keyFile = path.join(__dirname, 'fixtures', 'keys', 'default')

  const s = spawn('node', ['./bin/cli.js', 'sign', request, '-i', keyFile])
  const result = await dummySigner(s, { password: 'password' })

  t.ok(result.response)
  t.absent(result.isHyperdrive)

  const v = spawn('node', ['./bin/cli.js', 'verify', '-i', keyFile, response, request])
  t.ok(await dummyVerifier(v))
})

test('e2e - v2 core fixture', async (t) => {
  const request = await fs.readFile(
    path.join(__dirname, 'fixtures', 'requests', 'default.v2.core'),
    'utf8'
  )
  const response = await fs.readFile(
    path.join(__dirname, 'fixtures', 'responses', 'default.v2.core'),
    'utf8'
  )

  const keyFile = path.join(__dirname, 'fixtures', 'keys', 'default')

  const s = spawn('node', ['./bin/cli.js', 'sign', request, '-i', keyFile])
  const result = await dummySigner(s, { password: 'password' })

  t.ok(result.response)
  t.absent(result.isHyperdrive)

  const v = spawn('node', ['./bin/cli.js', 'verify', '-i', keyFile, response, request])
  t.ok(await dummyVerifier(v))
})

test('e2e - v2 drive fixture', async (t) => {
  const request = await fs.readFile(
    path.join(__dirname, 'fixtures', 'requests', 'default.v2.drive'),
    'utf8'
  )
  const response = await fs.readFile(
    path.join(__dirname, 'fixtures', 'responses', 'default.v2.drive'),
    'utf8'
  )

  const keyFile = path.join(__dirname, 'fixtures', 'keys', 'default')

  const s = spawn('node', ['./bin/cli.js', 'sign', '-i', keyFile, request])
  const result = await dummySigner(s, { password: 'password' })

  t.ok(result.response)
  t.ok(result.isHyperdrive)

  const v = spawn('node', ['./bin/cli.js', 'verify', '-i', keyFile, response, request])
  t.ok(await dummyVerifier(v))
})

test('e2e - migrate legacy keys', async (t) => {
  t.plan(6)

  const request = await fs.readFile(
    path.join(__dirname, 'fixtures', 'requests', 'v2-drive.request'),
    'utf8'
  )

  const dir = await t.tmp()
  const src = path.join(__dirname, 'fixtures', 'keys')

  await fs.cp(path.join(src, 'default.v0'), path.join(dir, 'default'))
  await fs.cp(path.join(src, 'default.public'), path.join(dir, 'default.public'))

  const env = {
    ...process.env,
    HYPERCORE_SIGN_KEYS_DIRECTORY: dir
  }

  const legacyKey = await fs.readFile(path.join(dir, 'default'), 'utf8')
  const legacyInfo = getKeyInfo(z32.decode(legacyKey))

  t.is(legacyInfo.version, 0)

  const proc = spawn('node', ['./bin/cli.js', 'sign', request], { env })

  const result = await dummySigner(proc, { password: 'password', migrate: true })

  t.ok(result.migrated, 'did migrate')
  t.absent(result.response, 'did not sign')

  const key = await fs.readFile(path.join(dir, 'default'), 'utf8')
  const info = getKeyInfo(z32.decode(key))

  t.is(info.version, 1)

  const backupKey = await fs.readFile(path.join(dir, 'default.v3.backup'), 'utf8')
  t.is(backupKey, legacyKey, 'backup is same as original key')
  t.not(backupKey, key, 'backup is different from migrated key')
})

test('e2e - do not migrate legacy keys', async (t) => {
  t.plan(6)

  const request = await fs.readFile(
    path.join(__dirname, 'fixtures', 'requests', 'v2-drive.request'),
    'utf8'
  )

  const dir = await t.tmp()
  const src = path.join(__dirname, 'fixtures', 'keys')

  await fs.cp(path.join(src, 'default.v0'), path.join(dir, 'default'))
  await fs.cp(path.join(src, 'default.public'), path.join(dir, 'default.public'))

  const env = {
    ...process.env,
    HYPERCORE_SIGN_KEYS_DIRECTORY: dir
  }

  const legacyKey = await fs.readFile(path.join(dir, 'default'), 'utf8')
  const legacyInfo = getKeyInfo(z32.decode(legacyKey))

  t.is(legacyInfo.version, 0)

  const proc = spawn('node', ['sign.js', request], { env })

  const result = await dummySigner(proc, { password: 'password', migrate: false })

  t.absent(result.migrated, 'did not migrate')
  t.ok(result.response, 'signed')

  const key = await fs.readFile(path.join(dir, 'default'), 'utf8')
  const info = getKeyInfo(z32.decode(key))

  t.is(info.version, 0)

  await t.exception(fs.stat(path.join(dir, 'default.v3.backup')), 'backup does not exist')
  t.alike(legacyKey, key, 'key did not change')
})
