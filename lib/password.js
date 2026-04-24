const sodium = require('sodium-native')
const securePrompt = require('secure-prompt')

const MIN_PASSWORD_LENGTH = 8

let pipeBuffer = null
const pipeLines = []
let pipeEnded = false
let pipeError = null
let pipeReaderStarted = false
let pipeWaiter = null

module.exports = {
  confirmPassword,
  readPassword
}

async function confirmPassword(pwd) {
  const check = await readPassword('Confirm password: ')

  if (pwd.byteLength !== check.byteLength) {
    sodium.sodium_memzero(pwd)
    sodium.sodium_memzero(check)

    sodium.sodium_free(pwd)
    sodium.sodium_free(check)

    return false
  }

  sodium.sodium_mprotect_readonly(pwd)
  sodium.sodium_mprotect_readwrite(check)

  const cmp = sodium.sodium_memcmp(pwd, check)

  sodium.sodium_memzero(check)
  sodium.sodium_free(check)

  sodium.sodium_mprotect_noaccess(pwd)

  return cmp
}

// function to accept password from user
async function readPassword(prompt = 'Keypair password: ') {
  // wait for stdin to release
  await new Promise((resolve) => setTimeout(resolve, 100))

  const pwd = process.stdin.isTTY
    ? await readPasswordFromTTY(prompt)
    : await readPasswordFromPipe(prompt)

  if (pwd.byteLength < MIN_PASSWORD_LENGTH) {
    sodium.sodium_memzero(pwd)
    sodium.sodium_free(pwd)
    throw new Error(`Password must be at least ${MIN_PASSWORD_LENGTH} characters`)
  }

  return pwd
}

async function readPasswordFromTTY(prompt) {
  process.stdout.write(prompt)

  const pwd = await securePrompt()

  process.stdout.write('\n') // secure prompt squashes line break
  return pwd
}

// `secure-prompt` loses buffered lines in non-TTY mode, so keep a persistent
// line queue for piped input and consume one answer per prompt.
async function readPasswordFromPipe(prompt) {
  process.stdout.write(prompt)

  let line = null
  try {
    line = await readLineFromPipe()
    process.stdout.write('\n')
    return toSecureBuffer(line)
  } finally {
    stopPipeReader()
    if (line !== null) line.fill(0)
  }
}

function startPipeReader() {
  if (pipeReaderStarted) return

  pipeReaderStarted = true
  process.stdin.on('data', onPipeData)
  process.stdin.on('end', onPipeEnd)
  process.stdin.on('error', onPipeError)
  process.stdin.resume()
}

function readLineFromPipe() {
  if (pipeLines.length > 0) return pipeLines.shift()
  if (pipeError !== null) throw pipeError
  if (pipeEnded) throw new Error('Prompt cancelled')

  startPipeReader()

  return new Promise((resolve, reject) => {
    pipeWaiter = { resolve, reject }
  })
}

function stopPipeReader() {
  if (!pipeReaderStarted) return

  pipeReaderStarted = false
  process.stdin.off('data', onPipeData)
  process.stdin.off('end', onPipeEnd)
  process.stdin.off('error', onPipeError)
  process.stdin.pause()
}

function onPipeData(chunk) {
  appendPipeBuffer(chunk)
  queuePipeLines()
  flushPipeWaiter()
}

function onPipeEnd() {
  pipeEnded = true
  queuePipeLines()
  flushPipeWaiter()
}

function onPipeError(err) {
  pipeError = err
  flushPipeWaiter()
}

function flushPipeWaiter() {
  if (pipeWaiter === null) return

  const { resolve, reject } = pipeWaiter
  pipeWaiter = null

  if (pipeLines.length > 0) {
    resolve(pipeLines.shift())
    return
  }

  if (pipeError !== null) {
    reject(pipeError)
    return
  }

  if (pipeEnded) {
    reject(new Error('Prompt cancelled'))
    return
  }

  pipeWaiter = { resolve, reject }
}

function queuePipeLines() {
  while (true) {
    const line = extractPipeLine()
    if (line === null) return
    pipeLines.push(line)
  }
}

function appendPipeBuffer(chunk, length = chunk.byteLength) {
  if (length === 0) return

  if (pipeBuffer === null) {
    pipeBuffer = Buffer.alloc(length)
    chunk.copy(pipeBuffer, 0, 0, length)
    return
  }

  const combined = Buffer.alloc(pipeBuffer.byteLength + length)
  pipeBuffer.copy(combined, 0)
  chunk.copy(combined, pipeBuffer.byteLength, 0, length)

  pipeBuffer.fill(0)
  pipeBuffer = combined
}

function extractPipeLine() {
  if (pipeBuffer === null || pipeBuffer.byteLength === 0) return null

  for (let i = 0; i < pipeBuffer.byteLength; i++) {
    const byte = pipeBuffer[i]
    if (byte !== 10 && byte !== 13) continue

    let nextStart = i + 1
    if (byte === 13 && nextStart < pipeBuffer.byteLength && pipeBuffer[nextStart] === 10) {
      nextStart++
    }

    return consumePipeLine(i, nextStart)
  }

  if (!pipeEnded) return null

  return consumePipeLine(pipeBuffer.byteLength, pipeBuffer.byteLength)
}

function consumePipeLine(lineEnd, nextStart) {
  const line = Buffer.alloc(lineEnd)
  const leftoverLength = pipeBuffer.byteLength - nextStart
  const leftover = leftoverLength > 0 ? Buffer.alloc(leftoverLength) : null

  if (lineEnd > 0) pipeBuffer.copy(line, 0, 0, lineEnd)
  if (leftover !== null) pipeBuffer.copy(leftover, 0, nextStart)

  pipeBuffer.fill(0)
  pipeBuffer = leftover

  return line
}

function toSecureBuffer(line) {
  const secure = sodium.sodium_malloc(Math.max(line.byteLength, 1))

  sodium.sodium_mprotect_readwrite(secure)
  if (line.byteLength > 0) line.copy(secure, 0)

  const result = secure.subarray(0, line.byteLength)
  sodium.sodium_mprotect_noaccess(result)

  return result
}
