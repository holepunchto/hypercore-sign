const t = process.stdout.isTTY

const c = (code) => (t ? (s) => `\x1b[${code}m${s}\x1b[0m` : (s) => s)

module.exports = {
  bold: c('1'),
  dim: c('2'),
  cyan: c('36'),
  yellow: c('33'),
  green: c('32'),
  red: c('31'),
  magenta: c('35'),
  gray: c('90')
}
