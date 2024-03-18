const readline = require('readline')
const z32 = require('z32')

module.exports = {
  userPrompt,
  userConfirm,
  formatHypercoreRequest,
  formatHyperdriveRequest,
  box,
  underline
}

async function userPrompt (prompt = '> ', fallback = null) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  })

  while (true) {
    const answer = await new Promise(resolve => {
      rl.question(prompt, line => {
        if (!line.length && fallback) resolve(fallback)
        else resolve(line.trim().toLowerCase())
      })
    })

    if (!answer.length && fallback === null) {
      prompt = 'A value must be specified: '
      continue
    }

    rl.close()
    process.stdout.write('\n')

    return answer.length ? answer : fallback
  }
}

async function userConfirm (prompt = 'Confirm? [y/N] ') {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  })

  while (true) {
    const answer = await new Promise(resolve => {
      rl.question(prompt, line => {
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
            prompt = '\nAnswer with y[es] or n[o]: '
            resolve(null)
        }
      })
    })

    if (answer === null) continue

    rl.close()
    return answer
  }
}

function formatHypercoreRequest (req) {
  return {
    core: req.id,
    fork: req.fork,
    length: req.length,
    treeHash: req.treeHash.toString('hex'),
    signers: req.manifest.signers.map(s => z32.encode(s.publicKey))
  }
}

function formatHyperdriveRequest (req) {
  return {
    key: req.id,
    fork: req.fork,
    metadata: {
      length: req.length,
      treeHash: req.treeHash.toString('hex')
    },
    content: {
      length: req.content.length,
      treeHash: req.content.treeHash.toString('hex')
    },
    signers: req.manifest.signers.map(s => z32.encode(s.publicKey))
  }
}

function box (text) {
  const mid = '\u2502 ' + text + ' \u2502'
  const top = '\u250c'.padEnd(mid.length - 1, '\u2500') + '\u2510'
  const btm = '\u2514'.padEnd(mid.length - 1, '\u2500') + '\u2518'

  return [top, mid, btm].join('\n')
}

function underline (text) {
  const mid = '\u2502 ' + text + '  '
  const btm = '\u2514'.padEnd(mid.length, '\u2500')

  return [mid, btm].join('\n')
}
