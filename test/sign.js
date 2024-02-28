const { spawn } = require('child_process')
const fs = require('fs/promises')
const path = require('path')
const test = require('brittle')

const { dummySigner } = require('./helpers')

test('sign - basic', async t => {
  t.plan(2)

  const keyFile = path.resolve(__dirname, 'fixtures', 'keys', 'default')
  const request = await fs.readFile(path.resolve(__dirname, 'fixtures', 'requests', 'default.v1.core'), 'utf8')

  const s = spawn('node', ['./bin/cli.js', 'sign', request, '-i', keyFile])

  t.teardown(() => s.kill('SIGKILL'))

  s.on('close', (code) => { t.is(code, 0, 'Successfully signed request') })

  await t.execution(dummySigner(s))
})

test('sign - base command', async t => {
  t.plan(2)

  const keyFile = path.resolve(__dirname, 'fixtures', 'keys', 'default')
  const request = await fs.readFile(path.resolve(__dirname, 'fixtures', 'requests', 'default.v1.core'), 'utf8')

  const s = spawn('node', ['./bin/cli.js', request, '-i', keyFile])

  t.teardown(() => s.kill('SIGKILL'))

  s.on('close', (code) => { t.is(code, 0, 'Successfully signed request') })

  await t.execution(dummySigner(s))
})

test('sign - with directory', async t => {
  t.plan(2)

  const storageDir = path.resolve(__dirname, 'fixtures', 'storage')
  const request = await fs.readFile(path.resolve(__dirname, 'fixtures', 'requests', 'default.v1.core'), 'utf8')

  const s = spawn('node', ['./bin/cli.js', request, '-d', storageDir])

  t.teardown(() => s.kill('SIGKILL'))

  s.on('close', (code) => { t.is(code, 0, 'Successfully signed request') })

  await t.execution(dummySigner(s))
})

test('sign - drive request', async t => {
  t.plan(2)

  const keyFile = path.resolve(__dirname, 'fixtures', 'keys', 'default')
  const request = await fs.readFile(path.resolve(__dirname, 'fixtures', 'requests', 'default.v2.drive'), 'utf8')

  const s = spawn('node', ['./bin/cli.js', 'sign', request, '-i', keyFile])

  t.teardown(() => s.kill('SIGKILL'))

  s.on('close', (code) => { t.is(code, 0, 'Successfully signed request') })

  await t.execution(dummySigner(s))
})

test('sign - v1 request', async t => {
  t.plan(2)

  const keyFile = path.resolve(__dirname, 'fixtures', 'keys', 'default')
  const request = await fs.readFile(path.resolve(__dirname, 'fixtures', 'requests', 'default.v1.core'), 'utf8')

  const s = spawn('node', ['./bin/cli.js', 'sign', request, '-i', keyFile])

  t.teardown(() => s.kill('SIGKILL'))

  s.on('close', (code) => { t.is(code, 0, 'Successfully signed request') })

  await t.execution(dummySigner(s))
})

test('sign - specify public key file', async t => {
  t.plan(2)

  const keyFile = path.resolve(__dirname, 'fixtures', 'keys', 'default.public')
  const request = await fs.readFile(path.resolve(__dirname, 'fixtures', 'requests', 'default.v2.core'), 'utf8')

  const s = spawn('node', ['./bin/cli.js', 'sign', request, '-i', keyFile])

  t.teardown(() => s.kill('SIGKILL'))

  s.on('close', (code) => { t.is(code, 0, 'Successfully signed request') })

  await t.execution(dummySigner(s))
})

test('sign - alternate signer', async t => {
  t.plan(2)

  const keyFile = path.resolve(__dirname, 'fixtures', 'keys', 'alternate')
  const request = await fs.readFile(path.resolve(__dirname, 'fixtures', 'requests', 'alternate.v2.core'), 'utf8')

  const s = spawn('node', ['./bin/cli.js', 'sign', request, '-i', keyFile])

  t.teardown(() => s.kill('SIGKILL'))

  s.on('close', (code) => { t.is(code, 0, 'Successfully signed request') })

  await t.execution(dummySigner(s))
})

test('sign - wrong signer', async t => {
  t.plan(2)

  const keyFile = path.resolve(__dirname, 'fixtures', 'keys', 'alternate')
  const request = await fs.readFile(path.resolve(__dirname, 'fixtures', 'requests', 'default.v2.core'), 'utf8')

  const s = spawn('node', ['./bin/cli.js', 'sign', request, '-i', keyFile])

  t.teardown(() => s.kill('SIGKILL'))

  s.on('close', (code) => { t.is(code, 1, 'Signing correctly exited') })

  await t.exception(dummySigner(s))
})

test('sign - bad password', async t => {
  t.plan(2)

  const keyFile = path.resolve(__dirname, 'fixtures', 'keys', 'default')
  const request = await fs.readFile(path.resolve(__dirname, 'fixtures', 'requests', 'default.v2.core'), 'utf8')

  const s = spawn('node', ['./bin/cli.js', 'sign', request, '-i', keyFile])

  t.teardown(() => s.kill('SIGKILL'))

  s.on('close', (code) => { t.is(code, 1, 'Signing correctly exited') })

  await t.exception(dummySigner(s, { password: 'drowssap' }))
})

test('sign - no keyfile', async t => {
  t.plan(2)

  const keyFile = path.resolve(__dirname, 'fixtures', 'keys', 'enoent')
  const request = await fs.readFile(path.resolve(__dirname, 'fixtures', 'requests', 'default.v2.core'), 'utf8')

  const s = spawn('node', ['./bin/cli.js', 'sign', request, '-i', keyFile])

  t.teardown(() => s.kill('SIGKILL'))

  s.on('close', (code) => { t.is(code, 1, 'Signing successfully errored') })

  await t.exception(dummySigner(s))
})

test('sign - does not confirm request', async t => {
  t.plan(1)

  const keyFile = path.resolve(__dirname, 'fixtures', 'keys', 'default')
  const request = await fs.readFile(path.resolve(__dirname, 'fixtures', 'requests', 'default.v2.core'), 'utf8')

  const s = spawn('node', ['./bin/cli.js', 'sign', request, '-i', keyFile])

  t.teardown(() => s.kill('SIGKILL'))

  s.on('close', (code) => { t.is(code, 1, 'Signing correctly exited') })

  dummySigner(s, { confirms: false })
})

test('sign - does not confirm key', async t => {
  t.plan(2)

  const keyFile = path.resolve(__dirname, 'fixtures', 'keys', 'default')
  const request = await fs.readFile(path.resolve(__dirname, 'fixtures', 'requests', 'default.v2.core'), 'utf8')

  const s = spawn('node', ['./bin/cli.js', 'sign', request, '-i', keyFile])

  t.teardown(() => s.kill('SIGKILL'))

  s.on('close', (code) => { t.is(code, 1, 'Signing correctly exited') })

  await t.exception(dummySigner(s, { confirms: ['yes', 'no'] }))
})

test('sign - user repeats prompt', async t => {
  t.plan(2)

  const keyFile = path.resolve(__dirname, 'fixtures', 'keys', 'default')
  const request = await fs.readFile(path.resolve(__dirname, 'fixtures', 'requests', 'default.v2.core'), 'utf8')

  const s = spawn('node', ['./bin/cli.js', 'sign', request, '-i', keyFile])

  t.teardown(() => s.kill('SIGKILL'))

  s.on('close', (code) => { t.is(code, 0, 'Signing correctly exited') })

  await t.execution(dummySigner(s, { confirms: ['repeat', 'y', 'repeat', 'y'] }))
})

test('sign - bad request', async t => {
  t.plan(2)

  const keyFile = path.resolve(__dirname, 'fixtures', 'keys', 'default')
  const request = await fs.readFile(path.resolve(__dirname, 'fixtures', 'requests', 'default.v2.core'), 'utf8')

  const s = spawn('node', ['./bin/cli.js', 'sign', request.slice(2), '-i', keyFile])

  t.teardown(() => s.kill('SIGKILL'))

  s.stderr.on('data', data => { t.pass('errored') })
  s.on('close', (code) => { t.is(code, 1, 'Signing correctly exited') })
})

test('sign - no args', async t => {
  t.plan(5)

  let message = ''

  const s = spawn('node', ['./bin/cli.js', 'sign'])

  s.stdout.on('data', data => {
    message += data.toString()
  })

  t.teardown(() => s.kill('SIGKILL'))

  s.on('close', (code) => {
    t.is(code, 1, 'Successfully created keys')
    t.ok(message.includes('hypercore-sign'))
    t.ok(message.includes('commands'))
    t.ok(message.includes('usage'))
  })

  t.is(await dummySigner(s), null)
})

test('sign - help', async t => {
  t.plan(5)

  const request = await fs.readFile(path.resolve(__dirname, 'fixtures', 'requests', 'default.v2.core'), 'utf8')

  let message = ''

  const s = spawn('node', ['./bin/cli.js', 'sign', request, '-h'])

  s.stdout.on('data', data => {
    message += data.toString()
  })

  t.teardown(() => s.kill('SIGKILL'))

  s.on('close', (code) => {
    t.is(code, 1, 'Successfully created keys')
    t.ok(message.includes('hypercore-sign'))
    t.ok(message.includes('commands'))
    t.ok(message.includes('usage'))
  })

  t.is(await dummySigner(s), null)
})
