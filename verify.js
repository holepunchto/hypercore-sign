#!/usr/bin/env node

const z32 = require('z32')

const { version } = require('./package.json')
const verify = require('./lib/verify')

async function main () {
  const response = process.argv[2]
  const signingRequest = process.argv[3]
  const pubkey = process.argv[4]
  if (!response || !signingRequest || !pubkey) {
    console.log(`hypercore-verify ${version}\n`)
    console.log('Verify a signed message.')
    console.log('\nUsage:')
    console.log('hypercore-verify <response> <signingRequest> <pubkey>\n')
    process.exit(1)
  }

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
    console.error(err)
    process.exit(1)
  }
}

main()
