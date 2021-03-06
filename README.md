# voatNacl
Use [SaltShaker](https://github.com/realrasengan/SaltShaker) (nacl) to encrypt/decrypt and sign/verify messages and posts on voat.co

This is a voat package using voat's new packaging system.  I've been playing around with it, and it seems really cool!


## How
1. Add metadata dependencies like this:

```

{
  "dependencies": {
    "u-realrasengan-nacl": "0.1.7"
  }
}

```
## How to use

```
voatNacl.sign("msg").then((r) => { console.log(r) });
= Signs with your pubkey.
= Returns signature

voatNacl.verify("msg","user").then((r) => { console.log(r) });
= Gets user's pubkey and verifies if they signed msg
= Returns msg if so, or null

voatNacl.encrypt("msg","user").then((r) => { console.log(r) });
= Encrypts a msg with user's pubkey and your privkey
= Returns a JSON obj with message (encrypted) and nonce.

voatNacl.decrypt("msg","nonce","user").then((r) => { console.log(r) });
= Decrypts an encrypted msg with given nonce and user's pubkey
= Returns the msg unencrypted

voatNacl.getUserPubkey("user")
= Gets their pubkey either from the voat page or from the localstorage
= Returns the pubkey

voatNacl.haveUserPubkey("user")
= Checks if we have the pubkey
= Returns true or false

```

## Examples

```

// sign and verify
voatNacl.sign("What's going on?").then((r) => {
  console.log(r);
  voatNacl.verify(r,"yourusername").then((r) => {
    console.log(r);
  });
});

// encrypt and decrypt
voatNacl.encrypt("What's going on?","yourusername").then((r) => {
  console.log(r);
  voatNacl.decrypt(r.message,r.nonce,"yourusername").then((r) => {
    console.log(r);
  });
});


```

## Deleting

Local Storage
```
window.localStorage.removeItem("voatnacl_pubkey_yourusername");
window.localStorage.removeItem("voatnacl_yourusername");

```

State

```

state.delete("voatnacl_encprivatekey");
state.delete("voatnacl_voatprivatekey");

```

## License

Copyright (c) 2019 realrasengan, PuttItOut

