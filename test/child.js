const prompt = require('secure-prompt')
const sodium = require('sodium-native')

async function main() {
  const buf = await prompt()
  sodium.sodium_mprotect_readonly(buf)
  process.stdout.write(buf.toString() + '\n')
  sodium.sodium_mprotect_noaccess(buf)
}

main().catch((err) => {
  process.stderr.write('subject error: ' + err.message + '\n')
  process.exit(1)
})
