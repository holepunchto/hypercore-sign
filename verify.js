#!/usr/bin/env node

const { version } = require('./package.json')
const verify = require('./lib/verify')

const usage = `
hypercore-verify ${version}

Verify a signed message.

hypercore-verify <response> <signingRequest> <pubkey>
`

async function main () {
  const response = process.argv[2]
  const signingRequest = process.argv[3]
  const pubkey = process.argv[4]

  try {
    const req = await verify(response, signingRequest, pubkey)
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
