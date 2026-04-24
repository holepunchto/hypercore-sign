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
yms6b1ku1qshe3n4g1w6449bnxjnedtxa6a8m1g693xwiwtk4bebzynafqtwj4tk8zud5k3ua6bxcfezydd18gtp6bso5ka91qe7qqhcyfmh1himkzz54i5drebdheqt3583ostjrcbg6hoczd3donejca3eimimph897bho4wfsx9pxnj1mc1mwb5i5togq468ro5wq4peu9gyn yedybsyxitbiwx6biqwqsyurnoi77arsr5y8autjh9u5a7c8u87jgto9yryyyyebyyjrdnoztcuyqf691y66z4bibugzyf1w9n7c68dsdgq7q5jsfncr8ynafqtwj4tk8zud5k3ua6bxcfezydd18gtp6bso5ka91qe7qqhcyy obcnze4r7eid53t7ic3hxyzsnwmobt3dues9y5epicx38rqz8qgy
```

## License

Apache-2.0
