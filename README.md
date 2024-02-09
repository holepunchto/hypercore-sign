# Hypercore Sign

Sign and verify hypercores at specific lengths.

## Install

```
npm i -g hypercore-sign
```

## Run

### Setup keys
Run this only once, to setup a public/private key pair in directory `~/.hypercore-sign`.

```
hypercore-sign-generate-keys
```

### Sign Hypercores

```
hypercore-sign <key> <length> <treeHash>
```

For example:
```
hypercore-sign oeeoz3w6fjjt7bym3ndpa6hhicm8f8naxyk11z4iypeoupn6jzpo 8915 je4ty6wu1rsezj8z19hudcr9xw8tfwojoi15rh8zkez1ttes6m1y
```

Note: hypercore-sign does **NOT** verify any hypercore semantics. In particular, it does not verify that the treeHash is correct for the specified version of the hypercore.

### Verify Signatures

```
hypercore-verify <signed-message> <signer-public-key>
```

For example:
```
hypercore-verify edfb1b3b3e423f55619e03ab066994484fd81d875af327a8b2e85ceba63676baed543c38a7656a76ec5ed832a053a7185d584dd3e799e7587a30ab807bb467006879706572636f7265206f65656f7a337736666a6a743762796d336e64706136686869636d3866386e6178796b31317a34697970656f75706e366a7a706f0a6c656e67746820383931350a7472656548617368206a65347479367775317273657a6a387a31396875646372397877387466776f6a6f6931357268387a6b657a3174746573366d3179 2fdf6b37381cbd54791a0608bf3617fb355fd8f2d95211e3ba8d91ce4d057ddd
```
