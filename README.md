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

## Commands

### `hypercore-sign`

Default mode is sign

### `hypercore-sign sign`

```
hypercore-sign <request>                  use default key: ~/.hypercore-sign/default
hypercore-sign <request> -i name          searches for key in ~/.hypercore-sign
hypercore-sign <request> -i /path/to/key  path to key file (relative or absolute)
```

Sign a hypercore signing request with your private key.

Expects the signing request to be [z32](z32)-encoded

For example:
```
hypercore-sign yr8oytuhdpmg4e511nj8thyo9mju1uaw8npox9dtzpo6ndu73w9xir69yryyyyebybywj5ifg81e8ikqbokxj1uehb1r6pkuex9s91axybjybajc47dhsgtjr9p58q8perk758qmxqn3idu5hiu5xw1iutce8xhmtmi6oxx3

# you will be prompted for a name and a password

> Choose a name...

> Key-pair password:...
```

### `hypercore-sign verify`

```
hypercore-sign verify <res> <req> <pubkey>    verify against a pubkey
hypercore-sign verify <res> <req> -i key      verify against a keyfile 
hypercore-sign verify <res> <req>             verify against all known keys
```

Verify the signed message against the given public key.

For example:
```
hypercore-verify yebyby5xzupiuamzhtcqrq4s3sh3msxjgdsdaf96saw7zb9amriic3asyryyyyebyyyonyebyryonyebyryonyebyryonyebyryonyebyryonyebyryonmwgo8copzwgshbtmt95cccpdj7xwdtg38e1brkd75do8rkmg1gpyy f4dedseg54dmqyaia97sgggtw6z4baucuwjy1fb67tad1ffujdgo
```


### `hypercore-sign generate`

Generate new key pairs.

```
hyeprcore-sign generate                    key pair saved at ~/.hypercore-sign/default
hyeprcore-sign generate /keys/directory    key pair saved to dir
```

By default `storage-dir` is set to `~/.hypercore-sign`.

You will be prompted to name the key pair and provide a password.

Keys are written with the following convention:
- secret key: `~/.hypercore-sign/default`
- public key: `~/.hypercore-sign/default.public`

```
hypercore-sign generate [key_dir]

# you will be prompted to name the key and provide a password
> key
> Key-pair password:...
```

### `hypercore-sign add`

Add known public keys.

```
add <key> <name>              key pair saved at ~/.hypercore-sign/known-peers
add <key> <name> -d <dir>     key pair saved to dir/known-peers
```

These will be used to verify requests if no pubkey is provided:

```
hypercore-sign verify <res> <req> -d <dir>    verify against all keys in dir/known-peers
```

## License

Apache-2.0
