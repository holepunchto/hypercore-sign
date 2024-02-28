#!/usr/bin/env node

const path = require('path')
const os = require('os')
const minimist = require('minimist')

const { version } = require('../package.json')

const { signer, verifier, generator, add } = require('../')
const { box, underline } = require('../lib/utils')

const argv = minimist(process.argv.slice(2), {
  alias: {
    help: 'h',
    id: 'i',
    'storage-dir': 'd'
  },
  string: ['id', 'storage-dir'],
  boolean: ['help']
})

const helpMsg = `${box(`hypercore-sign ${version}`)}

Utility for signing and verifying hypercore requests

${underline('commands')}

hypercore-sign [-h|--help] [-i|--id] [-d|--storage-dir] command

hypercore-sign sign             sign requests (default)
hypercore-sign verify           verify responses
hypercore-sign generate         generate new key pairs
hypercore-sign add              add trusted keys

${underline('usage')}

sign <request>                  use default key: ~/.hypercore-sign/default
sign <request> -i name          searches for key in ~/.hypercore-sign
sign <request> -i /path/to/key  path to key file (relative or absolute)
sign <request> -d ./storage     path to storage (relative or absolute)

verify <res> <req> <pubkey>     verify against a pubkey
verify <res> <req> -i key       verify against a keyfile
verify <res> <req> -d dir       verify against all keys in dir/known-peers

generate                        key pair saved at ~/.hypercore-sign/default
generate -d ./storage           key pair saved to ./storage

add <pubkey>                    key pair saved to ~/.hypercore-sign/known-peers
add <pubkey> -d <dir>           key pair saved to dir
add <pubkey> -d <dir> <name>    key pair saved as dir/name.public
`

if (argv.help || argv.h) {
  printHelp()
}

const homeDir = os.homedir()
let dir = path.join(homeDir, '.hypercore-sign')

if (argv.d) {
  dir = path.resolve(argv.d)
}

const keyPath = {
  dir,
  name: 'default'
}

if (argv.i) {
  parseKeyPath(argv.i, keyPath)
}

if (argv.d && keyPath.dir !== path.resolve(argv.d)) {
  throw new Error('Specified id is not within provided storage directory')
}

let [command, ...args] = argv._

switch (command) {
  case 'add': {
    const [publicKey, name] = args
    if (!publicKey) printHelp()
    else add(publicKey, path.join(keyPath.dir, 'known-peers'), name)
    break
  }

  case 'generate':
    generator(keyPath.dir)
    break

  case 'verify': {
    const [response, request, publicKey] = args
    if (!publicKey && !argv.i && !argv.d) {
      printHelp('No public key to verify against')
    }

    if (argv.d) {
      keyPath.name = ''
    } else {
      keyPath.ext = '.public'
    }

    verifier(response, request, publicKey || keyPath)
    break
  }

  case 'sign':
    if (!args.length) printHelp()
    else signer(args[0], keyPath)
    break

  default:
    args = argv._
    if (!args.length) printHelp()
    else signer(args[0], keyPath)
    break
}

function printHelp (msg) {
  console.log(helpMsg + (msg ? '\n' : ''))
  if (msg) console.error(msg)
  process.exit(1)
}

function parseKeyPath (arg, keyPath) {
  if (!arg) return keyPath

  const { dir, base, ext } = path.parse(arg)

  const split = base.split('.')
  keyPath.name = split.pop() === 'public' ? split.join('.') : base

  if (ext !== '.public') keyPath.name += ext // eg hypertele.readonly.public
  if (dir !== '') keyPath.dir = dir

  return keyPath
}
