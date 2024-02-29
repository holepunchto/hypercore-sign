const { spawn } = require('child_process')
const fs = require('fs/promises')
const path = require('path')
const test = require('brittle')

test('verify - basic', async t => {
  t.plan(2)

  const keyFile = path.resolve(__dirname, 'fixtures', 'keys', 'default.public')

  const pubkey = await fs.readFile(keyFile, 'utf8')

  const request = await fs.readFile(path.resolve(__dirname, 'fixtures', 'requests', 'default.v2.core'))
  const response = await fs.readFile(path.resolve(__dirname, 'fixtures', 'responses', 'default.v2.core'))

  const v = spawn('node', ['./bin/cli.js', 'verify', response, request, pubkey])

  t.teardown(() => v.kill('SIGKILL'))

  v.on('close', (code) => { t.is(code, 0, 'Successfully verified response') })

  await t.execution(new Promise((resolve, reject) => {
    v.stdout.on('data', data => {
      if (data.toString().includes('Signature verified.')) {
        resolve()
      }
    })

    v.stderr.on('data', (data) => {
      reject(new Error(data.toString()))
    })
  }))
})

test('verify - drive', async t => {
  t.plan(2)

  const keyFile = path.resolve(__dirname, 'fixtures', 'keys', 'default.public')

  const pubkey = await fs.readFile(keyFile, 'utf8')

  const request = await fs.readFile(path.resolve(__dirname, 'fixtures', 'requests', 'default.v2.drive'))
  const response = await fs.readFile(path.resolve(__dirname, 'fixtures', 'responses', 'default.v2.drive'))

  const v = spawn('node', ['./bin/cli.js', 'verify', response, request, pubkey])

  t.teardown(() => v.kill('SIGKILL'))

  v.on('close', (code) => { t.is(code, 0, 'Successfully verified response') })

  await t.execution(new Promise((resolve, reject) => {
    v.stdout.on('data', data => {
      if (data.toString().includes('Signature verified.')) {
        resolve()
      }
    })

    v.stderr.on('data', (data) => {
      reject(new Error(data.toString()))
    })
  }))
})

test('verify - specify key file', async t => {
  t.plan(2)

  const keyFile = path.resolve(__dirname, 'fixtures', 'keys', 'default.public')

  const request = await fs.readFile(path.resolve(__dirname, 'fixtures', 'requests', 'default.v2.core'))
  const response = await fs.readFile(path.resolve(__dirname, 'fixtures', 'responses', 'default.v2.core'))

  const v = spawn('node', ['./bin/cli.js', 'verify', response, request, '-i', keyFile])

  t.teardown(() => v.kill('SIGKILL'))

  v.on('close', (code) => { t.is(code, 0, 'Successfully verified response') })

  await t.execution(new Promise((resolve, reject) => {
    v.stdout.on('data', data => {
      if (data.toString().includes('Signature verified.')) {
        resolve()
      }
    })

    v.stderr.on('data', (data) => {
      reject(new Error(data.toString()))
    })
  }))
})

test('verify - specify key file no extension', async t => {
  t.plan(2)

  const keyFile = path.resolve(__dirname, 'fixtures', 'keys', 'default')

  const request = await fs.readFile(path.resolve(__dirname, 'fixtures', 'requests', 'default.v2.core'))
  const response = await fs.readFile(path.resolve(__dirname, 'fixtures', 'responses', 'default.v2.core'))

  const v = spawn('node', ['./bin/cli.js', 'verify', response, request, '-i', keyFile])

  t.teardown(() => v.kill('SIGKILL'))

  v.on('close', (code) => { t.is(code, 0, 'Successfully verified response') })

  await t.execution(new Promise((resolve, reject) => {
    v.stdout.on('data', data => {
      if (data.toString().includes('Signature verified.')) {
        resolve()
      }
    })

    v.stderr.on('data', (data) => {
      reject(new Error(data.toString()))
    })
  }))
})

test('verify - alternate key file', async t => {
  t.plan(2)

  const keyFile = path.resolve(__dirname, 'fixtures', 'keys', 'alternate.public')

  const request = await fs.readFile(path.resolve(__dirname, 'fixtures', 'requests', 'alternate.v2.core'))
  const response = await fs.readFile(path.resolve(__dirname, 'fixtures', 'responses', 'alternate.v2.core'))

  const v = spawn('node', ['./bin/cli.js', 'verify', response, request, '-i', keyFile])

  t.teardown(() => v.kill('SIGKILL'))

  v.on('close', (code) => { t.is(code, 0, 'Successfully verified response') })

  await t.execution(new Promise((resolve, reject) => {
    v.stdout.on('data', data => {
      if (data.toString().includes('Signature verified.')) {
        resolve()
      }
    })

    v.stderr.on('data', (data) => {
      reject(new Error(data.toString()))
    })
  }))
})

test('verify - wrong key file', async t => {
  t.plan(2)

  const keyFile = path.resolve(__dirname, 'fixtures', 'keys', 'alternate.public')

  const request = await fs.readFile(path.resolve(__dirname, 'fixtures', 'requests', 'default.v2.core'))
  const response = await fs.readFile(path.resolve(__dirname, 'fixtures', 'responses', 'default.v2.core'))

  const v = spawn('node', ['./bin/cli.js', 'verify', response, request, '-i', keyFile])

  t.teardown(() => v.kill('SIGKILL'))

  v.on('close', (code) => { t.is(code, 1, 'Successfully rejected response') })

  await t.exception(new Promise((resolve, reject) => {
    v.stdout.on('data', data => {
      if (data.toString().includes('Signature verified.')) {
        resolve()
      }
    })

    v.stderr.on('data', (data) => {
      reject(new Error('verification failed'))
    })
  }))
})

test('verify - wrong response', async t => {
  t.plan(2)

  const keyFile = path.resolve(__dirname, 'fixtures', 'keys', 'default.public')

  const request = await fs.readFile(path.resolve(__dirname, 'fixtures', 'requests', 'default.v2.core'))
  const response = await fs.readFile(path.resolve(__dirname, 'fixtures', 'responses', 'default.v2.drive'))

  const v = spawn('node', ['./bin/cli.js', 'verify', response, request, '-i', keyFile])

  t.teardown(() => v.kill('SIGKILL'))

  v.on('close', (code) => { t.is(code, 1, 'Successfully rejected response') })

  await t.exception(new Promise((resolve, reject) => {
    v.stdout.on('data', data => {
      if (data.toString().includes('Signature verified.')) {
        resolve()
      }
    })

    v.stderr.on('data', (data) => {
      reject(new Error('verification failed'))
    })
  }))
})

test('verify - bad request', async t => {
  t.plan(2)

  const keyFile = path.resolve(__dirname, 'fixtures', 'keys', 'default.public')

  const request = await fs.readFile(path.resolve(__dirname, 'fixtures', 'requests', 'default.v2.drive'))
  const response = await fs.readFile(path.resolve(__dirname, 'fixtures', 'responses', 'default.v2.drive'))

  const v = spawn('node', ['./bin/cli.js', 'verify', response, request.slice(2), '-i', keyFile])

  t.teardown(() => v.kill('SIGKILL'))

  v.on('close', (code) => { t.is(code, 1, 'Successfully rejected response') })

  await t.exception(new Promise((resolve, reject) => {
    v.stdout.on('data', data => {
      if (data.toString().includes('Signature verified.')) {
        resolve()
      }
    })

    v.stderr.on('data', (data) => {
      reject(new Error('verification failed'))
    })
  }))
})

test('verify - bad response', async t => {
  t.plan(2)

  const keyFile = path.resolve(__dirname, 'fixtures', 'keys', 'default.public')

  const request = await fs.readFile(path.resolve(__dirname, 'fixtures', 'requests', 'default.v2.drive'))
  const response = await fs.readFile(path.resolve(__dirname, 'fixtures', 'responses', 'default.v2.drive'))

  const v = spawn('node', ['./bin/cli.js', 'verify', response.slice(2), request, '-i', keyFile])

  t.teardown(() => v.kill('SIGKILL'))

  v.on('close', (code) => { t.is(code, 1, 'Successfully rejected response') })

  await t.exception(new Promise((resolve, reject) => {
    v.stdout.on('data', data => {
      if (data.toString().includes('Signature verified.')) {
        resolve()
      }
    })

    v.stderr.on('data', (data) => {
      reject(new Error('verification failed'))
    })
  }))
})

test('verify - bad public key', async t => {
  t.plan(2)

  const keyFile = path.resolve(__dirname, 'fixtures', 'keys', 'default.public')

  const pubkey = await fs.readFile(keyFile, 'utf8')

  const request = await fs.readFile(path.resolve(__dirname, 'fixtures', 'requests', 'default.v2.core'))
  const response = await fs.readFile(path.resolve(__dirname, 'fixtures', 'responses', 'default.v2.core'))

  const v = spawn('node', ['./bin/cli.js', 'verify', response, request, pubkey.slice(2)])

  t.teardown(() => v.kill('SIGKILL'))

  v.on('close', (code) => { t.is(code, 1, 'Successfully rejected response') })

  await t.exception(new Promise((resolve, reject) => {
    v.stdout.on('data', data => {
      if (data.toString().includes('Signature verified.')) {
        resolve()
      }
    })

    v.stderr.on('data', (data) => {
      reject(new Error('verification failed'))
    })
  }))
})

test('verify - no public key', async t => {
  t.plan(2)

  const request = await fs.readFile(path.resolve(__dirname, 'fixtures', 'requests', 'default.v2.core'))
  const response = await fs.readFile(path.resolve(__dirname, 'fixtures', 'responses', 'default.v2.core'))

  const v = spawn('node', ['./bin/cli.js', 'verify', response, request])

  t.teardown(() => v.kill('SIGKILL'))

  v.on('close', (code) => { t.is(code, 1, 'Successfully rejected response') })

  await t.exception(new Promise((resolve, reject) => {
    v.stdout.on('data', data => {
      if (data.toString().includes('Signature verified.')) {
        resolve()
      }
    })

    v.stderr.on('data', (data) => {
      reject(new Error('verification failed'))
    })
  }))
})

test('verify - no public key at location', async t => {
  t.plan(2)

  const keyFile = path.resolve(__dirname, 'fixtures', 'keys', 'none.public')

  const request = await fs.readFile(path.resolve(__dirname, 'fixtures', 'requests', 'default.v2.core'))
  const response = await fs.readFile(path.resolve(__dirname, 'fixtures', 'responses', 'default.v2.core'))

  const v = spawn('node', ['./bin/cli.js', 'verify', response, request, '-i', keyFile])

  t.teardown(() => v.kill('SIGKILL'))

  v.on('close', (code) => { t.is(code, 1, 'Successfully rejected response') })

  await t.exception(new Promise((resolve, reject) => {
    v.stdout.on('data', data => {
      if (data.toString().includes('Signature verified.')) {
        resolve()
      }
    })

    v.stderr.on('data', (data) => {
      reject(new Error('verification failed'))
    })
  }))
})

test('verify - storage dir', async t => {
  t.plan(2)

  const storageDir = path.resolve(__dirname, 'fixtures', 'storage') // alternate is trusted

  const request = await fs.readFile(path.resolve(__dirname, 'fixtures', 'requests', 'alternate.v2.core'))
  const response = await fs.readFile(path.resolve(__dirname, 'fixtures', 'responses', 'alternate.v2.core'))

  const v = spawn('node', ['./bin/cli.js', 'verify', response, request, '-d', storageDir])

  t.teardown(() => v.kill('SIGKILL'))

  v.on('close', (code) => { t.is(code, 0, 'Successfully verified response') })

  await t.execution(new Promise((resolve, reject) => {
    v.stdout.on('data', data => {
      if (data.toString().includes('Signature verified.')) {
        resolve()
      }
    })

    v.stderr.on('data', (data) => {
      reject(new Error('verification failed'))
    })
  }))
})

test('verify - storage dir, no corresponding key', async t => {
  t.plan(2)

  const storageDir = path.resolve(__dirname, 'fixtures', 'storage') // alternate is trusted

  const request = await fs.readFile(path.resolve(__dirname, 'fixtures', 'requests', 'default.v2.core'))
  const response = await fs.readFile(path.resolve(__dirname, 'fixtures', 'responses', 'default.v2.core'))

  const v = spawn('node', ['./bin/cli.js', 'verify', response, request, '-d', storageDir])

  t.teardown(() => v.kill('SIGKILL'))

  v.on('close', (code) => { t.is(code, 1, 'Successfully rejected response') })

  await t.exception(new Promise((resolve, reject) => {
    v.stdout.on('data', data => {
      if (data.toString().includes('Signature verified.')) {
        resolve()
      }
    })

    v.stderr.on('data', (data) => {
      reject(new Error('verification failed'))
    })
  }))
})

test('verify - storage dir conflicts key', async t => {
  t.plan(2)

  const storageDir = path.resolve(__dirname, 'fixtures', 'storage') // alternate is trusted
  const keyFile = path.resolve(__dirname, 'fixtures', 'keys', 'default.public') // alternate is trusted

  const request = await fs.readFile(path.resolve(__dirname, 'fixtures', 'requests', 'default.v2.core'))
  const response = await fs.readFile(path.resolve(__dirname, 'fixtures', 'responses', 'default.v2.core'))

  const v = spawn('node', ['./bin/cli.js', 'verify', response, request, '-d', storageDir, '-i', keyFile])

  t.teardown(() => v.kill('SIGKILL'))

  v.on('close', (code) => { t.is(code, 1, 'Successfully rejected response') })

  await t.exception(new Promise((resolve, reject) => {
    v.stdout.on('data', data => {
      if (data.toString().includes('Signature verified.')) {
        resolve()
      }
    })

    v.stderr.on('data', (data) => {
      reject(new Error('verification failed'))
    })
  }))
})

test('verify - help', async t => {
  t.plan(4)

  const keyFile = path.resolve(__dirname, 'fixtures', 'keys', 'default.public')

  const pubkey = await fs.readFile(keyFile, 'utf8')

  const request = await fs.readFile(path.resolve(__dirname, 'fixtures', 'requests', 'default.v2.core'))
  const response = await fs.readFile(path.resolve(__dirname, 'fixtures', 'responses', 'default.v2.core'))

  let message = ''

  const v = spawn('node', ['./bin/cli.js', 'verify', response, request, pubkey, '-h'])

  t.teardown(() => v.kill('SIGKILL'))

  v.stdout.on('data', data => {
    message += data.toString()
  })

  v.on('close', (code) => {
    t.is(code, 1, 'Successfully created keys')
    t.ok(message.includes('hypercore-sign'))
    t.ok(message.includes('commands'))
    t.ok(message.includes('usage'))
  })
})
