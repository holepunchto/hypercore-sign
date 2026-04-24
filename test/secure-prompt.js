const test = require('brittle')
const { spawn } = require('child_process')
const path = require('path')

test('secure-prompt reads from piped stdin twice', async (t) => {
  t.plan(3)
  t.timeout(5000)

  const PASSWORD = Math.random().toString().slice(2).padStart(8, 'x')

  const child = spawn(process.execPath, [path.join(__dirname, 'child.js')], {
    stdio: ['pipe', 'pipe', 'inherit']
  })
  t.teardown(() => child.kill('SIGKILL'))

  let output = ''

  child.stdout.on('data', (chunk) => {
    output += chunk.toString()
  })

  child.stdin.write(PASSWORD + '\n')
  child.stdin.write(PASSWORD + '\n')
  child.stdin.end()

  const [code, signal] = await new Promise((resolve) => {
    child.on('exit', (code, signal) => resolve([code, signal]))
  })

  t.is(signal, null, 'child was not killed by a signal')
  t.is(code, 0, 'child exited cleanly')
  t.ok(output.includes('Keys generated'), 'both prompts were answered')
})
