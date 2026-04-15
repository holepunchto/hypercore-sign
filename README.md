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

## Run

### Setup keys

Run this only once, to setup a public/private key pair.

By default, keys are written to:

- secret key: `~/.hypercore-sign/default`
- public key: `~/.hypercore-sign/default.public`

```
hypercore-sign-generate-keys

# you will be prompted for password
> Key-pair password:...
```

### Sign Hypercores

```
hypercore-sign <z32SigningRequest>
```

Sign a hypercore signing request with your private key.

Expects the signing request to be [z32](https://github.com/mafintosh/z32)-encoded

For example:

```
hypercore-sign yr8oytuhdpmg4e511nj8thyo9mju1uaw8npox9dtzpo6ndu73w9xir69yryyyyebybywj5ifg81e8ikqbokxj1uehb1r6pkuex9s91axybjybajc47dhsgtjr9p58q8perk758qmxqn3idu5hiu5xw1iutce8xhmtmi6oxx3

# you will be prompted for password
> Key-pair password:...
```

### Verify Signatures

```
hypercore-verify <signed-message> <signing-request> <signer-public-key>
```

Verify the signed message against the given signing request and public key.

For example:

```
hypercore-verify ybndrfg8ejkmcpqxot1uwisza345h769ybndrfg8ejkmcpqxot1uwisza345h769 yr8oytuhdpmg4e511nj8thyo9mju1uaw8npox9dtzpo6ndu73w9xir69yryyyyebybywj5ifg81e8ikqbokxj1uehb1r6pkuex9s91axybjybajc47dhsgtjr9p58q8perk758qmxqn3idu5hiu5xw1iutce8xhmtmi6oxx3 hu3rzup73iwuf35n458e54i3opmzo7wbbgisbuwmz7jr7jotgexo
```

## License

Apache-2.0
