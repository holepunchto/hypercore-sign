#!/usr/bin/env node

const { verify } = require('hypercore-sign-lib')
const z32 = require('z32')

const { version } = require('./package.json')

const usage = `
hypercore-verify ${version}

Verify a signed message.

hypercore-verify <response> <signingRequest> <pubkey>
`

async function main() {
  const response = process.argv[2]
  const signingRequest = process.argv[3]
  const pubkey = process.argv[4]

  if (!response || !signingRequest || !pubkey) {
    console.error('Error: missing input')
    console.log(usage)
    process.exit(1)
  }

  try {
    const req = await verify(z32.decode(response), z32.decode(signingRequest), z32.decode(pubkey))
    console.log('\nSignature verified.')
    console.log(`\n${pubkey} has signed the following request:`)
    console.log({
      core: req.id,
      fork: req.fork,
      length: req.length,
      treeHash: req.treeHash.toString('hex')
    })
  } catch (err) {
    if (err.message === 'Invalid arguments') {
      console.log(usage)
    } else {
      console.error(err)
    }
    process.exit(1)
  }
}

main()
