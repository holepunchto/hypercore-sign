const { spawn } = require('child_process')
const fs = require('fs/promises')
const path = require('path')
const tmp = require('test-tmp')
const test = require('brittle')

const { dummyUser } = require('./helpers')

test('generate - basic', async t => {
  t.plan(4)

  const keysDir = await tmp(t)

  const g = spawn('node', ['./bin/cli.js', 'generate', '-d', keysDir])

  t.teardown(() => g.kill('SIGKILL'))

  g.on('close', (code) => { t.is(code, 0, 'Successfully created keys') })

  const user = dummyUser(g)
  t.execution(user)

  const publicKey = await user

  const exp = await fs.readFile(path.join(keysDir, 'default.public'), 'utf-8')

  t.alike(publicKey, exp, 'Public key got written to file')

  await t.execution(() => fs.stat(path.join(keysDir, 'default')))
})

test('generate - keys already exist', async t => {
  t.plan(4)

  const keysDir = path.resolve(__dirname, 'fixtures', 'keys')
  const exp = await fs.readFile(path.join(keysDir, 'default.public'), 'utf-8')

  const g = spawn('node', ['./bin/cli.js', 'generate', '-d', keysDir])

  let message = ''

  g.stdout.on('data', data => {
    message += data.toString()
  })

  t.teardown(() => g.kill('SIGKILL'))

  g.on('close', (code) => {
    t.ok(message.includes('Secret key already written to'))
    t.ok(message.includes('Public key already written to'))
    t.ok(message.includes(keysDir))
  })

  t.is(await dummyUser(g), exp)
})

test('generate - named key', async t => {
  t.plan(4)

  const keysDir = await tmp(t)

  const g = spawn('node', ['./bin/cli.js', 'generate', '-d', keysDir])

  t.teardown(() => g.kill('SIGKILL'))

  g.on('close', (code) => { t.is(code, 0, 'Successfully created keys') })

  const user = dummyUser(g, { name: 'named' })
  await t.execution(user)

  const publicKey = await user

  const exp = await fs.readFile(path.join(keysDir, 'named.public'), 'utf-8')

  t.alike(publicKey, exp, 'Public key got written to file')

  await t.exception(() => fs.stat(path.join(keysDir, 'default')), /ENOENT/)
})

test('generate - password too short', async t => {
  t.plan(2)

  const keysDir = await tmp(t)

  const g = spawn('node', ['./bin/cli.js', 'generate', '-d', keysDir])

  t.teardown(() => g.kill('SIGKILL'))

  g.on('close', (code) => { t.is(code, 1, 'Key creation successfully errored') })

  const user = dummyUser(g, { password: 'short' })
  await t.exception(user)
})

test('generate - passwords do not match', async t => {
  t.plan(2)

  const keysDir = await tmp(t)

  const g = spawn('node', ['./bin/cli.js', 'generate', '-d', keysDir])

  t.teardown(() => g.kill('SIGKILL'))

  g.on('close', (code) => { t.is(code, 1, 'Key creation successfully errored') })

  const user = dummyUser(g, { confirmPassword: 'notpassword' })
  await t.exception(user)
})

test('generate - generate with just public key defined', async t => {
  t.plan(2)

  const keysDir = await tmp(t)

  const g = spawn('node', ['./bin/cli.js', 'generate', '-d', keysDir])

  t.teardown(() => g.kill('SIGKILL'))

  g.on('close', (code) => { t.is(code, 1, 'Key creation successfully errored') })

  const user = dummyUser(g, { confirmPassword: 'notpassword' })
  await t.exception(user)
})

test('generate - key with dots', async t => {
  t.plan(4)

  const keysDir = await tmp(t)

  const g = spawn('node', ['./bin/cli.js', 'generate', '-d', keysDir])

  t.teardown(() => g.kill('SIGKILL'))

  g.on('close', (code) => { t.is(code, 0, 'Key successfully created') })

  const user = dummyUser(g, { name: 'my.new.keypair' })
  await t.execution(user)

  const publicKey = await user

  const exp = await fs.readFile(path.join(keysDir, 'my.new.keypair.public'), 'utf-8')

  t.alike(publicKey, exp, 'Public key got written to file')

  await t.execution(() => fs.stat(path.join(keysDir, 'my.new.keypair')))
})

test('generate - help', async t => {
  t.plan(6)

  const keysDir = await tmp(t)

  let message = ''

  const g = spawn('node', ['./bin/cli.js', 'generate', '-d', keysDir, '-h'])

  g.stdout.on('data', data => {
    message += data.toString()
  })

  t.teardown(() => g.kill('SIGKILL'))

  g.on('close', (code) => {
    t.is(code, 1, 'Successfully created keys')
    t.ok(message.includes('hypercore-sign'))
    t.ok(message.includes('commands'))
    t.ok(message.includes('usage'))
  })

  t.is(await dummyUser(g), null)

  await t.exception(() => fs.stat(path.join(keysDir, 'default')), /ENOENT/)
})
