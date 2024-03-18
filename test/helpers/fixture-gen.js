const { spawn } = require('child_process')
const fs = require('fs')
const path = require('path')
const test = require('brittle')

const { getSigningRequest, getDriveSigningRequest } = require('./')

const fixtures = path.resolve(__dirname, '..', 'fixtures')
const rootDir = path.resolve(__dirname, '..', '..')

const name = process.argv[2] || 'default'
const version = process.argv[3] || 'v2'
const password = process.argv[4] || 'password'
const keyFile = path.join(fixtures, 'keys', name)

const prefix = name + '.' + version
const corePath = path.join(fixtures, 'requests', prefix + '.core')
const drivePath = path.join(fixtures, 'requests', prefix + '.drive')

test('generate fixture', async t => {
  t.plan(2)

  if (!name) {
    throw new Error('fixture name should be specified')
  }

  const publicKey = fs.readFileSync(keyFile + '.public', 'utf8')

  const core = await getSigningRequest(publicKey, t)
  const drive = await getDriveSigningRequest(publicKey, t)

  if (fs.existsSync(corePath) || fs.existsSync(drivePath)) {
    t.fail('fixture already exists, delete before overwriting')
    process.exit(1)
  }

  fs.writeFileSync(corePath, core.request, 'utf8')
  fs.writeFileSync(drivePath, drive.request, 'utf8')
})

test('generate responses', async t => {
  t.plan(2)

  if (!fs.existsSync(corePath) || !fs.existsSync(drivePath)) {
    t.fail('No fixture exists, have they been generated?')
    process.exit(1)
  }

  const coreReq = fs.readFileSync(corePath, 'utf8')
  const driveReq = fs.readFileSync(drivePath, 'utf8')

  const proc = spawn('node', [path.resolve(rootDir, './bin/cli.js'), '-i', keyFile, coreReq])

  t.teardown(() => proc.kill('SIGKILL'))

  proc.on('close', (code) => {
    t.is(code, 0, '0 status code for message signing process')
  })

  proc.stdout.on('data', (bufferData) => {
    const data = bufferData.toString().toLowerCase()

    if (data.includes('confirm?')) {
      // Enter the password
      proc.stdin.write('y\n')
    }

    if (data.includes('password')) {
      // Enter the password
      proc.stdin.write(password)
    }

    if (data.includes('reply with:')) {
      const response = data.split('reply with:')[1].trim()
      fs.writeFileSync(path.join(fixtures, 'responses', prefix + '.core'), response, 'utf8')
    }
  })

  const proc2 = spawn('node', [path.resolve(rootDir, './bin/cli.js'), '-i', keyFile, driveReq])

  t.teardown(() => proc2.kill('SIGKILL'))

  proc2.on('close', (code) => {
    t.is(code, 0, '0 status code for message signing process')
  })

  proc2.stdout.on('data', (bufferData) => {
    const data = bufferData.toString().toLowerCase()

    if (data.includes('confirm?')) {
      // Enter the password
      proc2.stdin.write('y\n')
    }

    if (data.includes('password')) {
      // Enter the password
      proc2.stdin.write(password)
    }

    if (data.includes('reply with:')) {
      const response = data.split('reply with:')[1].trim()
      fs.writeFileSync(path.join(fixtures, 'responses', prefix + '.drive'), response, 'utf8')
    }
  })
})
