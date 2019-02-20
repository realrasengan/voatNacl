// SaltShaker v1.0
//
// Use nacl (tweetnacl) easily to create public private keypairs to sign, verify
// encrypt and decrypt messages.
//
// Copyright (c) 2019 realrasengan
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
// THIS SOFTWARE IS UNAUDITED.  USE AT YOUR OWN RISK.

var SaltShaker = (function() {

  // Function:  _decoder.decode (internal)
  // Purpose:   converts an uint8array to a string
  // Returns:   string
  var _decoder = new TextDecoder();

  // Function:  create
  // Purpose:   creates a keypair (optionally from privatekey)
  // Returns:   {"publickey":publickey,"privatekey":privatekey}
  var create = function(privatekey) {
    var _keys = null;
    
    if(privatekey)
      _keys = nacl.sign.keyPair.fromSecretKey(nacl.util.decodeBase64(privatekey));
    else
      _keys = nacl.sign.keyPair();
    return {
      "publickey":nacl.util.encodeBase64(_keys.publicKey),
      "privatekey":nacl.util.encodeBase64(_keys.secretKey)
    }
  }

  // Function:  sign(msg, privkey)
  // Purpose:   uses a private key to sign a msg
  // Returns:   signed msg
  var sign = function(msg, privkey) {
    return nacl.util.encodeBase64(nacl.sign(nacl.util.decodeUTF8(msg),nacl.util.decodeBase64(privkey)));
  }

  // Function:  verify(signedmsg, pubkey)
  // Purpose:   uses a public key to verify a signed msg by the public key
  // Returns:   original msg derived from signed msg
  var verify = function(signedmsg, pubkey) {
    var _returnv = null;

    return ((_returnv = nacl.sign.open(nacl.util.decodeBase64(signedmsg),nacl.util.decodeBase64(pubkey))) ? _decoder.decode(_returnv) : null);
  }

  // Function:  encrypt(msg, pubkey, privkey)
  // Purpose:   uses a target's public key and a private key to encrypt a msg
  // Returns:   JSON object {"nonce":nonce,"message":msg}
  var encrypt = function(msg, pubkey, privkey) {
    var _nonce = nacl.randomBytes(nacl.box.nonceLength);

    return {
      "message":nacl.util.encodeBase64(nacl.box(nacl.util.decodeUTF8(msg),_nonce,ed2curve.convertPublicKey(nacl.util.decodeBase64(pubkey)),ed2curve.convertSecretKey(nacl.util.decodeBase64(privkey)))),
      "nonce":nacl.util.encodeBase64(_nonce)
    }
  }

  // Function:  decrypt(msg, nonce, pubkey, privkey)
  // Purpose:   uses a target's pubkey and a private key to decrypt a msg
  // Returns:   original msg decrypted from the encrypted msg
  var decrypt = function(msg, nonce, pubkey, privkey) {
    return _decoder.decode(nacl.box.open(nacl.util.decodeBase64(msg),nacl.util.decodeBase64(nonce),ed2curve.convertPublicKey(nacl.util.decodeBase64(pubkey)), ed2curve.convertSecretKey(nacl.util.decodeBase64(privkey))));
  }

  return {
    create: create,
    sign: sign,
    verify: verify,
    encrypt: encrypt,
    decrypt: decrypt
  }
})();
