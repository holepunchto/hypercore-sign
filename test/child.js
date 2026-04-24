const readline = require('readline')
const prompt = require('secure-prompt')
const sodium = require('sodium-native')

async function userConfirm(question = 'Confirm? [y/N] ') {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  })

  while (true) {
    const answer = await new Promise((resolve) => {
      rl.question(question, (line) => {
        if (!line.length) return resolve(false)

        const key = line[0].toLowerCase()

        switch (key) {
          case 'y':
            resolve(true)
            break
          case 'n':
            resolve(false)
            break
          default:
            question = '\nAnswer with y[es] or n[o]: '
            resolve(null)
        }
      })
    })

    if (answer === null) continue

    rl.close()

    // wait tick for stdin to release — same as sign.js
    await new Promise(setImmediate)

    return answer
  }
}

async function main() {
  await userConfirm()
  await userConfirm()

  process.stdout.write('Keypair password: ')
  const buf = await prompt()
  sodium.sodium_mprotect_readonly(buf)
  process.stdout.write(buf.toString() + '\n')
  sodium.sodium_mprotect_noaccess(buf)
}

main().catch((err) => {
  process.stderr.write('child error: ' + err.message + '\n')
  process.exit(1)
})
