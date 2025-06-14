const sodium = require('sodium-native')
const securePrompt = require('secure-prompt')

const MIN_PASSWORD_LENGTH = 8

module.exports = {
  confirmPassword,
  readPassword
}

async function confirmPassword (pwd) {
  const check = await readPassword('Confirm password: ')

  if (pwd.byteLength !== check.byteLength) return false

  sodium.sodium_mprotect_readonly(pwd)
  sodium.sodium_mprotect_readwrite(check)

  const cmp = sodium.sodium_memcmp(pwd, check)

  sodium.sodium_memzero(check)
  sodium.sodium_free(check)

  sodium.sodium_mprotect_noaccess(pwd)

  return cmp
}

// function to accept password from user
async function readPassword (prompt = 'Keypair password: ') {
  process.stdout.write(prompt)

  const pwd = await securePrompt()

  console.log()

  if (pwd.byteLength < MIN_PASSWORD_LENGTH) {
    throw new Error(`Password must be at least ${MIN_PASSWORD_LENGTH} characters`)
  }

  return pwd
}
