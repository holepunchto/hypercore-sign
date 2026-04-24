const test = require('brittle')
const { spawn } = require('child_process')
const path = require('path')

const RUNS = 20

test('secure-prompt reads from piped stdin', async (t) => {
  t.plan(3 * RUNS)
  t.timeout(3000 * RUNS)

  for (let i = 0; i < RUNS; i++) {
    const PASSWORD = Math.random().toString().slice(2).padStart(8, 'x')

    const child = spawn(process.execPath, [path.join(__dirname, 'child.js')], {
      stdio: ['pipe', 'pipe', 'inherit']
    })
    t.teardown(() => child.kill('SIGKILL'))

    let stdout = ''
    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString()
    })

    child.stdin.write(PASSWORD + '\n')
    child.stdin.end()

    const [code, signal] = await new Promise((resolve) => {
      child.on('exit', (code, signal) => resolve([code, signal]))
    })

    t.is(signal, null, `run ${i + 1}: child was not killed by a signal`)
    t.is(code, 0, `run ${i + 1}: child exited cleanly`)
    t.is(stdout.trim(), PASSWORD, `run ${i + 1}: received password matches`)
  }
})
