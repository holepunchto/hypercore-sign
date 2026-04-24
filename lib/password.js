const sodium = require('sodium-native')
const securePrompt = require('secure-prompt')

const MIN_PASSWORD_LENGTH = 8

module.exports = {
  confirmPassword,
  readPassword
}

async function confirmPassword(pwd) {
  const check = await readPassword('Confirm password: ')

  if (pwd.byteLength !== check.byteLength) {
    memzero(pwd)
    memzero(check)
    return false
  }

  sodium.sodium_mprotect_readonly(pwd)
  sodium.sodium_mprotect_readonly(check)

  const cmp = sodium.sodium_memcmp(pwd, check)

  memzero(check)

  if (!cmp) memzero(pwd)
  else sodium.sodium_mprotect_noaccess(pwd)

  return cmp
}

// function to accept password from user
async function readPassword(prompt = 'Keypair password: ') {
  process.stdout.write(prompt)

  const pwd = await securePrompt()

  process.stdout.write('\n') // secure prompt squashes line break

  if (pwd.byteLength < MIN_PASSWORD_LENGTH) {
    throw new Error(`Password must be at least ${MIN_PASSWORD_LENGTH} characters`)
  }

  return pwd
}

function memzero(buf) {
  sodium.sodium_mprotect_readwrite(buf)
  sodium.sodium_memzero(buf)
  sodium.sodium_free(buf)
}
