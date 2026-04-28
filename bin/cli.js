#!/usr/bin/env node

const path = require('path')
const os = require('os')

const { header, command, flag, arg, rest, bail, summary, validate } = require('paparam')

const { version } = require('../package.json')

const {
  signer: signHandler,
  verifier: verifyHandler,
  generator: generateHandler,
  add: addHandler
} = require('../')

const homeDir = os.homedir()
const defaultDir =
  process.env.HYPERCORE_SIGN_KEYS_DIRECTORY || path.join(homeDir, '.hypercore-sign')

const helpMsg = `hypercore-sign v${version}

  hypercore-sign [-h|--help] command

  Utility for signing and verifying hypercore requests

  Commands:
    sign                        sign requests
    verify                      verify responses
    generate                    generate new key pairs
    add                         add trusted keys
`

const cmd = command('base', arg('<command>'), rest('[...app-args]'), route)

const signCmd = command(
  'sign',
  header(`hypercore-sign v${version}`),
  summary('Sign a hypercore request'),
  flag('--storage-dir|-d [path]', 'storage directory (default ~/.hypercore-sign)'),
  flag('--identity|-i [name|path]', 'identity'),
  arg('<request>'),
  bail(() => console.log(signCmd.help())),
  sign
)

const verifyCmd = command(
  'verify',
  header(`hypercore-sign v${version}`),
  summary('Verify a response'),
  flag('--storage-dir|-d [path]', 'storage directory (default ~/.hypercore-sign)'),
  flag('--identity|-i [name|path]', 'identity'),
  arg('<response>'),
  arg('<request>'),
  arg('[publicKey]'),
  validate((p) => !!(p.args.publicKey || p.flags.d || p.flags.i), 'public key is not specified'),
  bail(() => console.log(verifyCmd.help())),
  verify
)

const generateCmd = command(
  'generate',
  header(`hypercore-sign v${version}`),
  summary('Generate a key pair'),
  flag('--storage-dir|-d <path>', 'storage directory (default ~/.hypercore-sign)'),
  bail(() => console.log(generateCmd.help())),
  generate
)

const addCmd = command(
  'add',
  header(`hypercore-sign v${version}`),
  summary('Add a known key'),
  flag('--storage-dir|-d <path>', 'storage directory (default ~/.hypercore-sign)'),
  arg('<publicKey>'),
  arg('[alias]'),
  validate((p) => !!p.args.publicKey, 'public key is required'),
  bail(() => console.log(addCmd.help())),
  add
)

cmd.parse()

function mainHelp() {
  console.log(helpMsg)
}

function route(p) {
  switch (p.args.command) {
    case 'sign':
      signCmd.parse(p.rest)
      break
    case 'verify':
      verifyCmd.parse(p.rest)
      break
    case 'generate':
      generateCmd.parse(p.rest)
      break
    case 'add':
      addCmd.parse(p.rest)
      break
    default:
      mainHelp()
  }
}

function sign(p) {
  signHandler(p.args.request, parseKeyPath(p, { name: 'default' }))
}

function verify(p) {
  const keyPath = parseKeyPath(p, { dir: 'known-peers', publicKey: true })
  const { response, request, publicKey } = p.args

  verifyHandler(response, request, publicKey || keyPath)
}

function generate(p) {
  const keyPath = parseKeyPath(p)
  generateHandler(keyPath.dir)
}

function add(p) {
  const keyPath = parseKeyPath(p, { dir: 'known-peers' })
  const { publicKey, alias } = p.args
  addHandler(publicKey, keyPath.dir, alias)
}

function parseKeyPath(p, { name, dir, publicKey = false } = {}) {
  const keyPath = {
    dir: defaultDir,
    name,
    ext: ''
  }

  const { identity, storageDir } = p.flags

  if (storageDir) {
    keyPath.dir = storageDir
  }

  if (dir) {
    keyPath.dir = path.join(keyPath.dir, dir)
  }

  if (identity) {
    const id = path.parse(identity)

    if (id.dir) keyPath.dir = id.dir
    keyPath.name = id.name
    keyPath.ext = id.ext || (publicKey ? '.public' : '')
  }

  return keyPath
}
