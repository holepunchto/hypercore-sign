#!/usr/bin/env node

const path = require('path')
const os = require('os')
const minimist = require('minimist')

const { version } = require('../package.json')

const { signer, verifier, generator } = require('../')
const { box, underline } = require('../lib/utils')

const argv = minimist(process.argv.slice(2), {
  alias: {
    help: 'h',
    id: 'i'
  },
  string: ['id'],
  boolean: ['help']
})

const helpMsg = `${box(`hypercore-sign ${version}`)}

Utility for signing and verifying hypercore requests

${underline('commands')}

hypercore-sign             (default command is sign)

hypercore-sign sign             sign requests
hypercore-sign verify           verify responses
hypercore-sign generate         generate new key pairs

${underline('usage')}

sign <request>                  use default key: ~/.hypercore-sign/default
sign <request> -i name          searches for key in ~/.hypercore-sign
sign <request> -i /path/to/key  path to key file (relative or absolute)

verify <res> <req> <pubkey>     verify against a pubkey
verify <res> <req> -i key       verify against a keyfile 
verify <res> <req>              verify against all known keys

generate                        key pair saved at ~/.hypercore-sign/default
generate /keys/directory        key pair saved to dir
`

if (argv.help || argv.h) {
  printHelp()
}

const homeDir = os.homedir()

const keyPath = {
  dir: path.join(homeDir, '.hypercore-sign'),
  name: 'default'
}

if (argv.i) {
  console.log(argv.i)
  parseKeyPath(argv.i, keyPath)
}

let [command, ...args] = argv._

switch (command) {
  case 'generate':
    generator(args[0] || keyPath.dir)
    break

  case 'verify': {
    const [response, request, publicKey] = args
    if (!publicKey && !argv.i) {
      printHelp('No public key to verify against')
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
