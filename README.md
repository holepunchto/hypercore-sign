# Hypercore Sign

Sign [hypercore signing requests](https://github.com/holepunchto/hypercore-signing-request/) using public/private key cryptography, and verify the signatures.

The flow is:
- The signer creates a public/private key pair, and shares the public key
- The signer signs Hypercores (for example to approve of their content at a certain length), and shares the signed message.
- Anyone with the public key can verify that the hypercore was indeed approved by the signer.

## Install

```
npm i -g hypercore-sign
```

## Usage

- Run with [hypercore-sign-cli](https://github.com/holepunchto/hypercore-sign-cli)

- API
```js
import { sign, verify } from 'hypercore-sign'
```

## License

Apache-2.0
