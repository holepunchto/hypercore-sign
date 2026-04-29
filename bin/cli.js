#!/usr/bin/env node

const path = require('path')
const os = require('os')

const { header, command, flag, arg, bail, summary, validate } = require('paparam')

const { version } = require('../package.json')

const { bold, dim, cyan, gray } = require('../lib/color')

const {
  signer: signHandler,
  verifier: verifyHandler,
  generator: generateHandler,
  add: addHandler
} = require('../')

const homeDir = os.homedir()
const defaultDir =
  process.env.HYPERCORE_SIGN_KEYS_DIRECTORY || path.join(homeDir, '.hypercore-sign')

const helpMsg = `${bold('hypercore-sign')} ${gray('v' + version)}

  hypercore-sign [-h|--help] command

  ${dim('Utility for signing and verifying hypercore requests')}

  Commands:
    ${cyan('sign')}                        sign requests
    ${cyan('verify')}                      verify responses
    ${cyan('generate')}                    generate new key pairs
    ${cyan('add')}                         add trusted keys
`

// commands

const signCmd = command(
  'sign',
  header(`hypercore-sign v${version}`),
  summary('Sign a hypercore request'),
  flag('--storage-dir|-d [path]', 'storage directory (default ~/.hypercore-sign)'),
  flag('--identity|-i [name|path]', 'identity'),
  arg('<request>'),
  validate(validateSign),
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
  validate(validateVerify),
  bail(() => console.log(verifyCmd.help())),
  verify
)

const generateCmd = command(
  'generate',
  header(`hypercore-sign v${version}`),
  summary('Generate a key pair'),
  flag('--storage-dir|-d <path>', 'storage directory (default ~/.hypercore-sign)'),
  validate(validateGenerate),
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
  validate(validateAdd),
  bail(() => console.log(addCmd.help())),
  add
)

const cmd = command('hypercore-sign', signCmd, verifyCmd, generateCmd, addCmd, bail(mainHelp))

cmd.parse()

// routers

function sign(p) {
  console.log(dim('signing') + ' ' + gray(p.args.request))
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

// validators

function validateSign(p) {
  return !!p.args.request
}

function validateVerify(p) {
  return !!(p.args.response && p.args.request && (p.args.publicKey || p.flags.d || p.flags.i))
}

function validateGenerate(p) {
  return true
}

function validateAdd(p) {
  return !!p.args.publicKey
}

// helpers

function mainHelp() {
  console.log(helpMsg)
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
