const sodium = require('sodium-native')
const securePrompt = require('secure-prompt')
const { encryptKey, decryptKey } = require('encrypted-key')

const MIN_PASSWORD_LENGTH = 8

module.exports = {
  generateKeys,
  sign,
  confirmPassword,
  readPassword,
  hash
}

function generateKeys (pwd) {
  const publicKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)

  sodium.crypto_sign_keypair(publicKey, secretKey)

  sodium.sodium_mprotect_readwrite(pwd)

  let encrypted = null
  try {
    encrypted = encryptKey(secretKey, pwd)
  } finally {
    sodium.sodium_memzero(pwd)
    sodium.sodium_free(pwd)
  }

  // TODO: also return id? (needs change in encrypted-key)
  return {
    publicKey,
    secretKey: encrypted
  }
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

function sign (signables, keyBuffer, pwd) {
  sodium.sodium_mprotect_readwrite(pwd)
  let secretKey = null
  try {
    secretKey = decryptKey(keyBuffer, pwd)
  } finally {
    sodium.sodium_memzero(pwd)
    sodium.sodium_free(pwd)
  }

  const signatures = []
  for (const { signable } of signables) {
    const signature = Buffer.alloc(sodium.crypto_sign_BYTES)
    sodium.crypto_sign_detached(signature, signable, secretKey)
    signatures.push(signature)
  }

  sodium.sodium_memzero(secretKey)

  return signatures
}

// function to accept password from user
async function readPassword (prompt = 'Keypair password: ') {
  process.stdout.write(prompt)

  const pwd = await securePrompt()

  if (pwd.byteLength < MIN_PASSWORD_LENGTH) {
    throw new Error(`Password must be at least ${MIN_PASSWORD_LENGTH} characters`)
  }

  return pwd
}

function hash (data) {
  const output = Buffer.alloc(sodium.crypto_generichash_BYTES)
  sodium.crypto_generichash(output, data)

  return output
}
