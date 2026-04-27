#!/usr/bin/env node

const path = require('path')
const os = require('os')
const minimist = require('minimist')

const { header, footer, command, flag, arg, summary, description, rest } = require('paparam')

const { version } = require('../package.json')

const { signer, verifier, generator, add } = require('../')
const { box, underline } = require('../lib/utils')

const cmd = command(
  'sign',
  summary('Sign a hypercore request'),
  flag('--storage-dir|-d <path>', 'storage directory (default ~/.hypercore-sign')
  flag('--identity|-i <name|path>', 'identity')
  arg('<request>'),
  validate(p => !!(p.args.publicKey || p.flags.d || p.flags.i), 'public key is not specified')
  sign
)

const cmd = command(
  'verify',
  summary('Verify a response'),
  flag('--storage-dir|-d <path>', 'storage directory (default ~/.hypercore-sign')
  flag('--identity|-i <name|path>', 'identity')
  arg('<response>'),
  arg('<request>'),
  arg('[publicKey]'),
  validate(p => !!(p.args.publicKey || p.flags.d || p.flags.i), 'public key is not specified')
  verify
)

const cmd = command(
  'generate',
  summary('Generate a key pair'),
  flag('--storage-dir|-d <path>', 'storage directory (default ~/.hypercore-sign')
  generate
)

const cmd = command(
  'add',
  summary('Add a known key'),
  flag('--storage-dir|-d <path>', 'storage directory (default ~/.hypercore-sign')
  arg('<publicKey>'),
  arg('[alias]'),
  validate(p => !!p.publicKey, 'public key is required')
  add
)

cmd.parse()

const homeDir = os.homedir()
const defaultDir = path.join(homeDir, '.hypercore-sign')

function sign(p) {
  signer(p.args.request, parseKeyPath(p))
}

function verify(p) {
  const keyPath = parseKeyPath(p, { publicKey: true })
  const { response, request, publicKey } = p.args

  verifier(response, request, publicKey || keyPath)
}

function generate(p) {
  const keyPath = parseKeyPath(p)
  generator(keyPath.dir)
}

function add(p) {
  const keyPath = parseKeyPath(p)
  const { publicKey, name } = p.args
  else add(publicKey, path.join(keyPath.dir, 'known-peers'), name)
  break
}

function parseKeyPath(p, { dir, publicKey = true }) {
  const keyPath = {
    dir: defaultDir,
    name: 'default',
    ext: publicKey ? '.public' : ''
  }

  const { id, storageDir } = p.flags 

  if (storageDir) {
    keyPath.dir = storageDir
  }

  if (identity) {
    const id = path.parse(identity)

    if (id.dir) keyPath.dir = id.dir
    keyPath.name = id.name
    keyPath.ext = id.ext
  }

  return keyPath
}
