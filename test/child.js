const prompt = require('secure-prompt')
const sodium = require('sodium-native')

async function readPassword(msg) {
  process.stdout.write(msg)
  const buf = await prompt()
  sodium.sodium_mprotect_readonly(buf)
  const str = buf.toString()
  sodium.sodium_mprotect_noaccess(buf)
  return str
}

async function main() {
  const password = await readPassword('Keypair password: ')
  const confirm = await readPassword('Confirm password: ')

  if (password !== confirm) {
    process.stderr.write('Passwords do not match\n')
    process.exit(1)
  }

  process.stdout.write('Keys generated\n')
}

main().catch((err) => {
  process.stderr.write('child error: ' + err.message + '\n')
  process.exit(1)
})
