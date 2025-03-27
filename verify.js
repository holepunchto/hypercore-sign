#!/usr/bin/env node

const verify = require('./lib/verify')

async function main () {
  const response = process.argv[2]
  const signingRequest = process.argv[3]
  const pubkey = process.argv[4]

  try {
    await verify(response, signingRequest, pubkey)
  } catch (err) {
    console.error(err)
    process.exit(1)
  }
}

main()
