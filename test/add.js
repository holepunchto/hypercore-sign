const { spawn } = require('child_process')
const fs = require('fs/promises')
const path = require('path')
const tmp = require('test-tmp')
const z32 = require('z32')
const test = require('brittle')

test('add - basic', async t => {
  const storageDir = await tmp(t)

  const pubkey = await fs.readFile(path.join(__dirname, 'fixtures', 'keys', 'default.public'), 'utf8')

  const t1 = t.test()
  t1.plan(4)

  const a = spawn('node', ['./bin/cli.js', 'add', pubkey, 'default', '-d', storageDir])

  t1.teardown(() => a.kill('SIGKILL'))

  a.on('close', (code) => { t1.is(code, 0, 'Successfully added key') })

  let message = ''

  a.stdout.on('data', data => {
    message += data.toString()
  })

  a.stderr.on('data', (data) => {
    t1.fail('Adding key errored')
  })

  a.on('close', code => {
    const lines = message.split('\n').filter(m => m.length)
    t1.is(lines.length, 2)

    const savePath = lines[0].split('Public key saved as ')[1]
    const publicKey = lines[1].split('Public key is ')[1]

    t1.is(savePath, path.join(storageDir, 'known-peers', 'default.public'))
    t1.is(publicKey, pubkey)
  })

  await t1
})

test('add - name prompt', async t => {
  t.plan(4)

  const storageDir = await tmp(t)

  const pubkey = await fs.readFile(path.join(__dirname, 'fixtures', 'keys', 'default.public'), 'utf8')

  const a = spawn('node', ['./bin/cli.js', 'add', pubkey, '-d', storageDir])

  t.teardown(() => a.kill('SIGKILL'))

  a.on('close', (code) => { t.is(code, 0, 'Successfully added key') })

  let message = ''

  a.stdout.on('data', data => {
    if (data.toString().toLowerCase().includes('choose a name')) {
      a.stdin.write('named\n')
    }

    message += data.toString()
  })

  a.stderr.on('data', (data) => {
    t.fail('Adding key errored')
  })

  a.on('close', code => {
    const lines = message.split('\n').filter(m => m.length)
    t.is(lines.length, 3)

    const savePath = lines[1].split('Public key saved as ')[1]
    const publicKey = lines[2].split('Public key is ')[1]

    t.is(savePath, path.join(storageDir, 'known-peers', 'named.public'))
    t.is(publicKey, pubkey)
  })
})

test('add - name prompt, no value specifed', async t => {
  t.plan(5)

  const storageDir = await tmp(t)

  const pubkey = await fs.readFile(path.join(__dirname, 'fixtures', 'keys', 'default.public'), 'utf8')

  const a = spawn('node', ['./bin/cli.js', 'add', pubkey, '-d', storageDir])

  t.teardown(() => a.kill('SIGKILL'))

  a.on('close', (code) => { t.is(code, 0, 'Successfully added key') })

  let message = ''

  a.stdout.on('data', data => {
    const d = data.toString().toLowerCase()
    if (d.includes('choose a name')) {
      a.stdin.write('\n')
    } else if (d.includes('must be specified')) {
      a.stdin.write('named\n')
    }

    message += data.toString() + '\n'
  })

  a.stderr.on('data', (data) => {
    t.fail('Adding key errored')
  })

  a.on('close', code => {
    const lines = message.split('\n').filter(m => m.length)
    t.is(lines.length, 4)

    t.is(lines[1], 'A value must be specified: ')

    const savePath = lines[2].split('Public key saved as ')[1]
    const publicKey = lines[3].split('Public key is ')[1]

    t.is(savePath, path.join(storageDir, 'known-peers', 'named.public'))
    t.is(publicKey, pubkey)
  })
})

test('add - bad key', async t => {
  t.plan(2)

  const storageDir = await tmp(t)

  const pubkey = await fs.readFile(path.join(__dirname, 'fixtures', 'keys', 'default.public'), 'utf8')
  const badKey = z32.encode(z32.decode(pubkey).slice(2))

  const a = spawn('node', ['./bin/cli.js', 'add', badKey, 'default', '-d', storageDir])
  a.stdout.pipe(process.stdout)

  t.teardown(() => a.kill('SIGKILL'))

  a.on('close', (code) => { t.is(code, 1, 'Successfully rejected key') })

  a.stderr.on('data', (data) => {
    t.pass('Adding key errored')
  })
})

test('add - invalid key', async t => {
  t.plan(2)

  const storageDir = await tmp(t)

  const badKey = z32.encode(Buffer.alloc(32))

  const a = spawn('node', ['./bin/cli.js', 'add', badKey, 'default', '-d', storageDir])
  a.stdout.pipe(process.stdout)

  t.teardown(() => a.kill('SIGKILL'))

  a.on('close', (code) => { t.is(code, 1, 'Successfully rejected key') })

  a.stderr.on('data', (data) => {
    t.pass('Adding key errored')
  })
})

test('add - verify', async t => {
  const storageDir = await tmp(t)

  const pubkey = await fs.readFile(path.join(__dirname, 'fixtures', 'keys', 'default.public'), 'utf8')
  const request = await fs.readFile(path.resolve(__dirname, 'fixtures', 'requests', 'default.v2.core'))
  const response = await fs.readFile(path.resolve(__dirname, 'fixtures', 'responses', 'default.v2.core'))

  const a = spawn('node', ['./bin/cli.js', 'add', pubkey, 'default', '-d', storageDir])

  const t1 = t.test()
  t1.plan(4)

  t1.teardown(() => a.kill('SIGKILL'))

  a.on('close', (code) => { t1.is(code, 0, 'Successfully added key') })

  let message = ''

  a.stdout.on('data', data => {
    message += data.toString()
  })

  a.stderr.on('data', (data) => {
    t1.fail('Adding key errored')
  })

  let savePath
  a.on('close', code => {
    const lines = message.split('\n').filter(m => m.length)
    t1.is(lines.length, 2)

    savePath = lines[0].split('Public key saved as ')[1]
    const publicKey = lines[1].split('Public key is ')[1]

    t1.is(savePath, path.join(storageDir, 'known-peers', 'default.public'))
    t1.is(publicKey, pubkey)
  })

  await t1

  const t2 = t.test()
  t2.plan(4)

  const v = spawn('node', ['./bin/cli.js', 'verify', response, request, '-d', storageDir])

  t2.teardown(() => v.kill('SIGKILL'))

  message = ''

  v.stdout.on('data', data => {
    message += data.toString()
  })

  v.stderr.on('data', (data) => {
    t2.fail('Verification failed')
  })

  v.on('close', code => {
    t2.is(code, 0, 'Successfully signed request')
    t2.ok(message.includes('Signature verified'))
    t2.ok(message.includes('Signed by known peer'))
    t2.ok(message.includes(savePath))
  })
})

test('add - under different name', async t => {
  const storageDir = await tmp(t)

  const pubkey = await fs.readFile(path.join(__dirname, 'fixtures', 'keys', 'default.public'), 'utf8')
  const request = await fs.readFile(path.resolve(__dirname, 'fixtures', 'requests', 'default.v2.core'))
  const response = await fs.readFile(path.resolve(__dirname, 'fixtures', 'responses', 'default.v2.core'))

  const a = spawn('node', ['./bin/cli.js', 'add', pubkey, 'test', '-d', storageDir])

  const t1 = t.test()
  t1.plan(4)

  t1.teardown(() => a.kill('SIGKILL'))

  a.on('close', (code) => { t1.is(code, 0, 'Successfully added key') })

  let message = ''

  a.stdout.on('data', data => {
    message += data.toString()
  })

  a.stderr.on('data', (data) => {
    t1.fail('Adding key errored')
  })

  let savePath
  a.on('close', code => {
    const lines = message.split('\n').filter(m => m.length)
    t1.is(lines.length, 2)

    savePath = lines[0].split('Public key saved as ')[1]
    const publicKey = lines[1].split('Public key is ')[1]

    t1.is(savePath, path.join(storageDir, 'known-peers', 'test.public'))
    t1.is(publicKey, pubkey)
  })

  await t1

  const t2 = t.test()
  t2.plan(4)

  const v = spawn('node', ['./bin/cli.js', 'verify', response, request, '-d', storageDir])

  t2.teardown(() => v.kill('SIGKILL'))

  message = ''

  v.stdout.on('data', data => {
    message += data.toString()
  })

  v.stderr.on('data', (data) => {
    t2.fail('Verification failed')
  })

  v.on('close', code => {
    t2.is(code, 0, 'Successfully signed request')
    t2.ok(message.includes('Signature verified'))
    t2.ok(message.includes('Signed by known peer'))
    t2.ok(message.includes(savePath))
  })
})

test('add - no key found', async t => {
  const storageDir = await tmp(t)

  const pubkey = await fs.readFile(path.join(__dirname, 'fixtures', 'keys', 'alternate.public'), 'utf8')
  const request = await fs.readFile(path.resolve(__dirname, 'fixtures', 'requests', 'default.v2.core'))
  const response = await fs.readFile(path.resolve(__dirname, 'fixtures', 'responses', 'default.v2.core'))

  const a = spawn('node', ['./bin/cli.js', 'add', pubkey, 'default', '-d', storageDir])

  const t1 = t.test()
  t1.plan(4)

  t1.teardown(() => a.kill('SIGKILL'))

  a.on('close', (code) => { t1.is(code, 0, 'Successfully added key') })

  let message = ''

  a.stdout.on('data', data => {
    message += data.toString()
  })

  a.stderr.on('data', (data) => {
    t1.fail('Adding key errored')
  })

  let savePath
  a.on('close', code => {
    const lines = message.split('\n').filter(m => m.length)
    t1.is(lines.length, 2)

    savePath = lines[0].split('Public key saved as ')[1]
    const publicKey = lines[1].split('Public key is ')[1]

    t1.is(savePath, path.join(storageDir, 'known-peers', 'default.public'))
    t1.is(publicKey, pubkey)
  })

  await t1

  const t2 = t.test()
  t2.plan(5)

  const v = spawn('node', ['./bin/cli.js', 'verify', response, request, '-d', storageDir])

  t2.teardown(() => v.kill('SIGKILL'))

  message = ''

  v.stdout.on('data', data => {
    message += data.toString()
  })

  v.stderr.on('data', (data) => {
    t2.pass('Verification failed')
  })

  v.on('close', code => {
    t2.is(code, 1, 'Successfully signed request')
    t2.absent(message.includes('Signature verified'))
    t2.absent(message.includes('Signed by known peer'))
    t2.absent(message.includes(savePath))
  })
})
