const fsProm = require('fs/promises')
const path = require('path')
const test = require('brittle')
const { spawn } = require('child_process')
const tmp = require('test-tmp')
const z32 = require('z32')
const c = require('compact-encoding')

const { Response } = require('../lib/messages')
const {
  dummyUser,
  dummySigner,
  getSigningRequest,
  getDriveSigningRequest
} = require('./helpers')

const DUMMY_PASSWORD = Math.random().toString().slice(2).padStart(8, 'x')

test('e2e - sign a core', async t => {
  const keysDir = await tmp(t)

  const t1 = t.test()
  t1.plan(2)

  const g = spawn('node', ['./bin/cli.js', 'generate', '-d', keysDir])

  t1.teardown(() => g.kill('SIGKILL'))

  g.on('close', (code) => { t1.is(code, 0, 'Successfully created keys') })

  const publicKey = await dummyUser(g, { password: DUMMY_PASSWORD })
  const exp = await fsProm.readFile(path.join(keysDir, 'default.public'), 'utf-8')

  t1.alike(publicKey, exp, 'Public key got written to file')
  await t1

  const { request, verify } = await getSigningRequest(publicKey, t)

  const keyFile = path.join(keysDir, 'default')

  const t2 = t.test()
  t2.plan(2)

  const s = spawn('node', ['./bin/cli.js', 'sign', request, '-i', keyFile])

  t2.teardown(() => s.kill('SIGKILL'))

  s.on('close', (code) => { t2.is(code, 0, '0 status code for message signing process') })

  const signing = dummySigner(s, { password: DUMMY_PASSWORD })
  t2.execution(signing)

  const response = await signing

  await t2

  const t3 = t.test()
  t3.plan(2)

  const v = spawn('node', ['./bin/cli.js', 'verify', response, request, publicKey])

  t3.teardown(() => v.kill('SIGKILL'))

  v.on('close', (code) => { t3.is(code, 0, '0 status code for verify process') })

  let data = ''
  v.stdout.on('data', (bufferData) => {
    data += bufferData.toString()
  })

  v.stderr.on('data', (data) => {
    t3.fail('verify errored')
  })

  v.stdout.on('close', () => {
    if (data.includes('Signature verified.')) {
      if (data.includes(publicKey)) {
        t3.pass('Verified that the message got signed by the correct public key')
      } else {
        t3.fail('Message was signed by an incorrect public key--bug in test setup')
      }
    }
  })

  await t3

  // verify against actual core
  const { signatures } = c.decode(Response, z32.decode(response))
  t.ok(verify(signatures[0]))

  // sanity check
  signatures[0].signature.fill(0)
  t.absent(verify(signatures[0]))
})

test('e2e - sign a drive', async t => {
  const keysDir = await tmp(t)

  const t1 = t.test()
  t1.plan(2)

  const g = spawn('node', ['./bin/cli.js', 'generate', '-d', keysDir])

  t1.teardown(() => g.kill('SIGKILL'))

  g.on('close', (code) => { t1.is(code, 0, 'Successfully created keys') })

  const publicKey = await dummyUser(g, { password: DUMMY_PASSWORD })
  const exp = await fsProm.readFile(path.join(keysDir, 'default.public'), 'utf-8')

  t1.alike(publicKey, exp, 'Public key got written to file')
  await t1

  const { request, verify } = await getDriveSigningRequest(publicKey, t)

  const keyFile = path.join(keysDir, 'default')

  const t2 = t.test()
  t2.plan(2)

  const s = spawn('node', ['./bin/cli.js', 'sign', request, '-i', keyFile])

  t2.teardown(() => s.kill('SIGKILL'))

  s.on('close', (code) => { t2.is(code, 0, '0 status code for message signing process') })

  const signing = dummySigner(s, { password: DUMMY_PASSWORD })
  t2.execution(signing)

  const response = await signing

  await t2

  const t3 = t.test()
  t3.plan(2)

  const v = spawn('node', ['./bin/cli.js', 'verify', response, request, publicKey])

  t3.teardown(() => v.kill('SIGKILL'))

  v.on('close', (code) => { t3.is(code, 0, '0 status code for verify process') })

  let data = ''
  v.stdout.on('data', (bufferData) => {
    data += bufferData.toString()
  })

  v.stderr.on('data', (data) => {
    t3.fail('verify errored')
  })

  v.stdout.on('close', () => {
    if (data.includes('Signature verified.')) {
      if (data.includes(publicKey)) {
        t3.pass('Verified that the message got signed by the correct public key')
      } else {
        t3.fail('Message was signed by an incorrect public key--bug in test setup')
      }
    }
  })

  await t3

  // verify against actual core
  const { signatures } = c.decode(Response, z32.decode(response))
  t.ok(verify(signatures))

  // sanity check
  signatures[0].signature.fill(0)
  t.absent(verify(signatures))
})

test('e2e - v1 fixture', async t => {
  const request = await fsProm.readFile(path.join(__dirname, 'fixtures', 'requests', 'default.v1.core'), 'utf8')
  const response = await fsProm.readFile(path.join(__dirname, 'fixtures', 'responses', 'default.v1.core'), 'utf8')

  const keyFile = path.join(__dirname, 'fixtures', 'keys', 'default')

  const t1 = t.test()
  t1.plan(3)

  const s = spawn('node', ['./bin/cli.js', '-i', keyFile, request])

  t1.teardown(() => s.kill('SIGKILL'))

  s.on('close', (code) => {
    t1.is(code, 0, '0 status code for message signing process')
  })

  s.stdout.on('data', (bufferData) => {
    const data = bufferData.toString().toLowerCase()

    if (data.includes('confirm?')) {
      // Enter the password
      s.stdin.write('y\n')
    }

    if (data.includes('password')) {
      // Enter the password
      s.stdin.write('password')
    }

    if (data.includes('reply with:')) {
      t1.pass('Successfully signed the message')
    }

    if (data.includes('hypercore signing request')) {
      t1.pass()
    } else if (data.includes('hyperdrive signing request')) {
      t1.fail()
    }
  })

  s.stderr.on('data', (data) => {
    console.error(data.toString())
    t1.fail('sign errored')
  })

  await t1

  const t2 = t.test()
  t2.plan(2)

  const v = spawn('node', ['./bin/cli.js', 'verify', '-i', keyFile, response, request])

  t2.teardown(() => v.kill('SIGKILL'))

  v.on('close', (code) => {
    t2.is(code, 0, '0 status code for message signing process')
  })

  let data = ''
  v.stdout.on('data', (bufferData) => {
    data += bufferData.toString()
  })

  v.stderr.on('data', (data) => {
    t2.fail('verify errored')
  })

  v.stdout.on('close', () => {
    if (data.includes('Signature verified.')) {
      t2.pass('Verified that the message got signed by the correct public key')
    }
  })

  await t2
})

test('e2e - v2 core fixture', async t => {
  const request = await fsProm.readFile(path.join(__dirname, 'fixtures', 'requests', 'default.v2.core'), 'utf8')
  const response = await fsProm.readFile(path.join(__dirname, 'fixtures', 'responses', 'default.v2.core'), 'utf8')

  const keyFile = path.join(__dirname, 'fixtures', 'keys', 'default')

  const t1 = t.test()
  t1.plan(3)

  const s = spawn('node', ['./bin/cli.js', '-i', keyFile, request])

  t1.teardown(() => s.kill('SIGKILL'))

  s.on('close', (code) => {
    t1.is(code, 0, '0 status code for message signing process')
  })

  s.stdout.on('data', (bufferData) => {
    const data = bufferData.toString().toLowerCase()

    if (data.includes('confirm?')) {
      // Enter the password
      s.stdin.write('y\n')
    }

    if (data.includes('password')) {
      // Enter the password
      s.stdin.write('password')
    }

    if (data.includes('reply with:')) {
      t1.pass('Successfully signed the message')
    }

    if (data.includes('hypercore signing request')) {
      t1.pass()
    } else if (data.includes('hyperdrive signing request')) {
      t1.fail()
    }
  })

  s.stderr.on('data', (data) => {
    console.error(data.toString())
    t1.fail('sign errored')
  })

  await t1

  const t2 = t.test()
  t2.plan(3)

  const v = spawn('node', ['./bin/cli.js', 'verify', '-i', keyFile, response, request])

  t2.teardown(() => v.kill('SIGKILL'))

  v.on('close', (code) => {
    t2.is(code, 0, '0 status code for message signing process')
  })

  v.on('close', (code) => { t2.is(code, 0, '0 status code for verify process') })

  let data = ''
  v.stdout.on('data', (bufferData) => {
    data += bufferData.toString()
  })

  v.stderr.on('data', (data) => {
    t2.fail('verify errored')
  })

  v.stdout.on('close', () => {
    if (data.includes('Signature verified.')) {
      t2.pass('Verified that the message got signed by the correct public key')
    }
  })

  await t2
})

test('e2e - v2 drive fixture', async t => {
  const request = await fsProm.readFile(path.join(__dirname, 'fixtures', 'requests', 'default.v2.drive'), 'utf8')
  const response = await fsProm.readFile(path.join(__dirname, 'fixtures', 'responses', 'default.v2.drive'), 'utf8')

  const keyFile = path.join(__dirname, 'fixtures', 'keys', 'default')

  const t1 = t.test()
  t1.plan(3)

  const s = spawn('node', ['./bin/cli.js', '-i', keyFile, request])

  t1.teardown(() => s.kill('SIGKILL'))

  s.on('close', (code) => {
    t1.is(code, 0, '0 status code for message signing process')
  })

  s.stdout.on('data', (bufferData) => {
    const data = bufferData.toString().toLowerCase()

    if (data.includes('confirm?')) {
      // Enter the password
      s.stdin.write('y\n')
    }

    if (data.includes('password')) {
      // Enter the password
      s.stdin.write('password')
    }

    if (data.includes('reply with:')) {
      t1.pass('Successfully signed the message')
    }

    if (data.includes('hyperdrive signing request')) {
      t1.pass()
    } else if (data.includes('hypercore signing request')) {
      t1.fail()
    }
  })

  s.stderr.on('data', (data) => {
    console.error(data.toString())
    t1.fail('sign errored')
  })

  await t1

  const t2 = t.test()
  t2.plan(3)

  const v = spawn('node', ['./bin/cli.js', 'verify', '-i', keyFile, response, request])

  t2.teardown(() => v.kill('SIGKILL'))

  v.on('close', (code) => {
    t2.is(code, 0, '0 status code for message signing process')
  })

  v.on('close', (code) => { t2.is(code, 0, '0 status code for verify process') })

  let data = ''
  v.stdout.on('data', (bufferData) => {
    data += bufferData.toString()
  })

  v.stderr.on('data', (data) => {
    t2.fail('verify errored')
  })

  v.stdout.on('close', () => {
    if (data.includes('Signature verified.')) {
      t2.pass('Verified that the message got signed by the correct public key')
    }
  })

  await t2
})
