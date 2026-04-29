const readline = require('readline')
const z32 = require('z32')

const { bold, cyan, gray } = require('./color')

module.exports = {
  userPrompt,
  userConfirm,
  formatHypercoreRequest,
  formatHyperdriveRequest,
  box,
  underline,
  field
}

async function userPrompt(prompt = '> ', fallback = null) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  })

  while (true) {
    const answer = await new Promise((resolve) => {
      rl.question(prompt, (line) => {
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

async function userConfirm(prompt = 'Confirm? [y/N] ') {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  })

  while (true) {
    const answer = await new Promise((resolve) => {
      rl.question(prompt, (line) => {
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

    // wait tick for stdin to release
    await new Promise(setImmediate)

    return answer
  }
}

function formatHypercoreRequest(req) {
  const signers = req.manifest.signers.map((s) => z32.encode(s.publicKey))
  return [
    field('core', req.id),
    field('fork', req.fork),
    field('length', req.length),
    field('treeHash', req.treeHash.toString('hex')),
    ...signers.map((s, i) => field(i === 0 ? 'signers' : '', s))
  ].join('\n')
}

function formatHyperdriveRequest(req) {
  const signers = req.manifest.signers.map((s) => z32.encode(s.publicKey))
  return [
    field('key', req.id),
    field('fork', req.fork),
    section('metadata'),
    nestedField('length', req.length),
    nestedField('treeHash', req.treeHash.toString('hex')),
    section('content'),
    nestedField('length', req.content.length),
    nestedField('treeHash', req.content.treeHash.toString('hex')),
    ...signers.map((s, i) => field(i === 0 ? 'signers' : '', s))
  ].join('\n')
}

function box(text) {
  const inner = ' ' + text + ' '
  const top = '┌' + '─'.repeat(inner.length) + '┐'
  const btm = '└' + '─'.repeat(inner.length) + '┘'
  return [cyan(top), cyan('│') + bold(inner) + cyan('│'), cyan(btm)].join('\n')
}

function underline(text) {
  const inner = ' ' + text + '  '
  const btm = '└' + '─'.repeat(inner.length)
  return [cyan('│') + bold(inner), cyan(btm)].join('\n')
}

function field(label, value) {
  const str = Buffer.isBuffer(value) ? value.toString('hex') : String(value)
  return '  ' + gray(label.padEnd(10)) + cyan(str)
}

function section(label) {
  return '\n  ' + bold(gray(label))
}

function nestedField(label, value) {
  const str = Buffer.isBuffer(value) ? value.toString('hex') : String(value)
  return '    ' + gray(label.padEnd(10)) + cyan(str)
}
