const { spawn } = require('child_process')
const fs = require('fs/promises')
const path = require('path')
const test = require('brittle')

const { dummySigner, copyKeysDir } = require('./helpers')

test('sign - basic', async (t) => {
  t.plan(2)

  const dir = await t.tmp()

  await copyKeysDir(path.join(__dirname, 'fixtures', 'keys'), dir)
  const keyFile = path.resolve(dir, 'default')

  const request = await fs.readFile(
    path.resolve(__dirname, 'fixtures', 'requests', 'default.v1.core'),
    'utf8'
  )

  const s = spawn('node', ['./bin/cli.js', 'sign', request, '-i', keyFile])

  t.teardown(() => s.kill('SIGKILL'))

  s.on('close', (code) => t.is(code, 0))

  const result = await dummySigner(s)

  t.ok(result.response)
})

test('sign - base command', async (t) => {
  t.plan(2)

  const dir = await t.tmp()

  await copyKeysDir(path.join(__dirname, 'fixtures', 'keys'), dir)
  const keyFile = path.resolve(dir, 'default')

  const request = await fs.readFile(
    path.resolve(__dirname, 'fixtures', 'requests', 'default.v1.core'),
    'utf8'
  )

  const s = spawn('node', ['./bin/cli.js', 'sign', request, '-i', keyFile])

  t.teardown(() => s.kill('SIGKILL'))

  s.on('close', (code) => t.is(code, 0))

  const result = await dummySigner(s)

  t.ok(result.response)
})

test('sign - with directory', async (t) => {
  t.plan(2)

  const dir = await t.tmp()

  await copyKeysDir(path.join(__dirname, 'fixtures', 'storage'), dir)

  const request = await fs.readFile(
    path.resolve(__dirname, 'fixtures', 'requests', 'default.v1.core'),
    'utf8'
  )

  const s = spawn('node', ['./bin/cli.js', 'sign', request, '-d', dir])

  t.teardown(() => s.kill('SIGKILL'))

  s.on('close', (code) => t.is(code, 0))

  const result = await dummySigner(s)

  t.ok(result.response)
})

test('sign - drive request', async (t) => {
  t.plan(2)

  const dir = await t.tmp()

  await copyKeysDir(path.join(__dirname, 'fixtures', 'keys'), dir)
  const keyFile = path.resolve(dir, 'default')

  const request = await fs.readFile(
    path.resolve(__dirname, 'fixtures', 'requests', 'default.v2.drive'),
    'utf8'
  )

  const s = spawn('node', ['./bin/cli.js', 'sign', request, '-i', keyFile])

  t.teardown(() => s.kill('SIGKILL'))

  s.on('close', (code) => t.is(code, 0))

  const result = await dummySigner(s)

  t.ok(result.response)
})

test('sign - v1 request', async (t) => {
  t.plan(2)

  const dir = await t.tmp()

  await copyKeysDir(path.join(__dirname, 'fixtures', 'keys'), dir)
  const keyFile = path.resolve(dir, 'default')

  const request = await fs.readFile(
    path.resolve(__dirname, 'fixtures', 'requests', 'default.v1.core'),
    'utf8'
  )

  const s = spawn('node', ['./bin/cli.js', 'sign', request, '-i', keyFile])

  t.teardown(() => s.kill('SIGKILL'))

  s.on('close', (code) => t.is(code, 0))

  const result = await dummySigner(s)

  t.ok(result.response)
})

test('sign - alternate signer', async (t) => {
  t.plan(2)

  const dir = await t.tmp()

  await copyKeysDir(path.join(__dirname, 'fixtures', 'keys'), dir, { name: 'alternate' })
  const keyFile = path.resolve(dir, 'alternate')

  const request = await fs.readFile(
    path.resolve(__dirname, 'fixtures', 'requests', 'alternate.v2.core'),
    'utf8'
  )

  const s = spawn('node', ['./bin/cli.js', 'sign', request, '-i', keyFile])

  t.teardown(() => s.kill('SIGKILL'))

  s.on('close', (code) => t.is(code, 0))

  const result = await dummySigner(s)

  t.ok(result.response)
})

test('sign - wrong signer', async (t) => {
  t.plan(2)

  const dir = await t.tmp()

  await copyKeysDir(path.join(__dirname, 'fixtures', 'keys'), dir, { name: 'alternate' })
  const keyFile = path.resolve(dir, 'alternate')

  const request = await fs.readFile(
    path.resolve(__dirname, 'fixtures', 'requests', 'default.v2.core'),
    'utf8'
  )

  const s = spawn('node', ['./bin/cli.js', 'sign', request, '-i', keyFile])

  t.teardown(() => s.kill('SIGKILL'))

  s.on('close', (code) => t.is(code, 1))

  await t.exception(dummySigner(s))
})

test('sign - bad password', async (t) => {
  t.plan(2)

  const dir = await t.tmp()

  await copyKeysDir(path.join(__dirname, 'fixtures', 'keys'), dir)
  const keyFile = path.resolve(dir, 'default')

  const request = await fs.readFile(
    path.resolve(__dirname, 'fixtures', 'requests', 'default.v2.core'),
    'utf8'
  )

  const s = spawn('node', ['./bin/cli.js', 'sign', request, '-i', keyFile])

  t.teardown(() => s.kill('SIGKILL'))

  s.on('close', (code) => t.is(code, 1))

  await t.exception(dummySigner(s, { password: 'drowssap' }))
})

test('sign - no keyfile', async (t) => {
  t.plan(2)

  const keyFile = path.resolve(__dirname, 'fixtures', 'keys', 'enoent')
  const request = await fs.readFile(
    path.resolve(__dirname, 'fixtures', 'requests', 'default.v2.core'),
    'utf8'
  )

  const s = spawn('node', ['./bin/cli.js', 'sign', request, '-i', keyFile])

  t.teardown(() => s.kill('SIGKILL'))

  s.on('close', (code) => t.is(code, 1))

  await t.exception(dummySigner(s))
})

test('sign - does not confirm request', async (t) => {
  t.plan(2)

  const dir = await t.tmp()

  await copyKeysDir(path.join(__dirname, 'fixtures', 'keys'), dir)
  const keyFile = path.resolve(dir, 'default')

  const request = await fs.readFile(
    path.resolve(__dirname, 'fixtures', 'requests', 'default.v2.core'),
    'utf8'
  )

  const s = spawn('node', ['./bin/cli.js', 'sign', request, '-i', keyFile])

  t.teardown(() => s.kill('SIGKILL'))

  s.on('close', (code) => t.is(code, 1))

  await t.exception(dummySigner(s, { confirms: false }))
})

test('sign - does not confirm key', async (t) => {
  t.plan(2)

  const dir = await t.tmp()

  await copyKeysDir(path.join(__dirname, 'fixtures', 'keys'), dir)
  const keyFile = path.resolve(dir, 'default')

  const request = await fs.readFile(
    path.resolve(__dirname, 'fixtures', 'requests', 'default.v2.core'),
    'utf8'
  )

  const s = spawn('node', ['./bin/cli.js', 'sign', request, '-i', keyFile])

  t.teardown(() => s.kill('SIGKILL'))

  s.on('close', (code) => t.is(code, 1))

  await t.exception(dummySigner(s, { confirms: ['yes', 'no'] }))
})

test('sign - user repeats prompt', async (t) => {
  t.plan(1)

  const dir = await t.tmp()

  await copyKeysDir(path.join(__dirname, 'fixtures', 'keys'), dir)
  const keyFile = path.resolve(dir, 'default')

  const request = await fs.readFile(
    path.resolve(__dirname, 'fixtures', 'requests', 'default.v2.core'),
    'utf8'
  )

  const s = spawn('node', ['./bin/cli.js', 'sign', request, '-i', keyFile])

  t.teardown(() => s.kill('SIGKILL'))

  const result = await dummySigner(s, { confirms: ['repeat', 'y', 'repeat', 'y'] })

  t.ok(result.response)
})

test('sign - bad request', async (t) => {
  t.plan(2)

  const dir = await t.tmp()

  await copyKeysDir(path.join(__dirname, 'fixtures', 'keys'), dir)
  const keyFile = path.resolve(dir, 'default')

  const request = await fs.readFile(
    path.resolve(__dirname, 'fixtures', 'requests', 'default.v2.core'),
    'utf8'
  )

  const s = spawn('node', ['./bin/cli.js', 'sign', request.slice(2), '-i', keyFile])

  t.teardown(() => s.kill('SIGKILL'))

  let stderr = ''
  s.stderr.on('data', (data) => {
    stderr += data.toString()
  })
  s.on('close', (code) => {
    t.ok(stderr.includes('Could not decode the signing request'), 'errored')
    t.is(code, 1, 'Signing correctly exited')
  })
})

test('sign - no args', async (t) => {
  t.plan(5)

  let message = ''

  const s = spawn('node', ['./bin/cli.js', 'sign'])

  s.stdout.on('data', (data) => {
    message += data.toString()
  })

  t.teardown(() => s.kill('SIGKILL'))

  s.on('close', (code) => {
    t.is(code, 0, 'process exited')
    t.ok(message.includes('hypercore-sign'))
    t.ok(message.includes('Arguments'))
    t.ok(message.includes('Flags'))
  })

  await t.execution(dummySigner(s))
})

test('sign - help', async (t) => {
  t.plan(5)

  const request = await fs.readFile(
    path.resolve(__dirname, 'fixtures', 'requests', 'default.v2.core'),
    'utf8'
  )

  let message = ''

  const s = spawn('node', ['./bin/cli.js', 'sign', request, '-h'])

  s.stdout.on('data', (data) => {
    message += data.toString()
  })

  t.teardown(() => s.kill('SIGKILL'))

  s.on('close', (code) => {
    t.is(code, 0, 'process exited')
    t.ok(message.includes('hypercore-sign'))
    t.ok(message.includes('Arguments'))
    t.ok(message.includes('Flags'))
  })

  await t.execution(dummySigner(s))
})

test('sign - confirmation displays quorum and namespace', async (t) => {
  t.plan(3)

  const dir = await t.tmp()

  await copyKeysDir(path.join(__dirname, 'fixtures', 'keys'), dir)
  const keyFile = path.resolve(dir, 'default')

  const request = await fs.readFile(
    path.resolve(__dirname, 'fixtures', 'requests', 'default.v1.core'),
    'utf8'
  )

  const s = spawn('node', ['./bin/cli.js', 'sign', request, '-i', keyFile])

  t.teardown(() => s.kill('SIGKILL'))

  const output = await new Promise((resolve, reject) => {
    let out = ''

    s.stdout.on('data', (data) => {
      out += data.toString().toLowerCase()
      if (out.includes('confirm?')) resolve(out)
    })

    s.stderr.on('data', (data) => reject(new Error('process errored: ' + data.toString())))
  })

  t.ok(output.includes('quorum'), 'confirmation displays quorum')
  t.ok(output.includes('1 / 1'), 'quorum shows threshold out of signer count')
  t.ok(output.includes('namespace'), 'confirmation displays namespace')
})
