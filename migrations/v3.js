const z32 = require('z32')
const b4a = require('b4a')
const { migrate } = require('hypercore-sign-lib')

const { readPassword } = require('../lib/password.js')

async function migrateV3(key, publicKey) {
  const password = await readPassword()
  const migrated = await migrate(key, password)

  if (!migrated || !b4a.equals(migrated.publicKey, publicKey)) {
    throw new Error('Migration failed')
  }

  return z32.encode(migrated.secretKey)
}

module.exports = {
  migrateV3
}
