// voatNacl v0.1.2-alpha
// Use nacl to encrypt/decrypt and sign/verify messages and posts on voat.co
//
// Copyright (c) 2019 realrasengan on voat.co
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
// This software is UNAUDITED.  Use it at your own risk.
//
//
// voatNacl.signMessage(message).then((return_value) => {
// - Returns signature signed with publickey in [return_value]
//
// voatNacl.verifyMessage(message,user).then((return_value) => {  //
// - Returns [message] without signature in [return_value] if it is a valid signed message by [user] or [return_value=null]
//
// voatNacl.encryptMessage(message,user).then((return_value) => {
// - Returns {"nonce":NONCE,"message":ENCRYPTEDMSG} in [return_value]
//
// voatNacl.decryptMessage(message,user).then((return_value) => {
// - Returns [message] decrypted in [return_value] or [return_value=null] with [user]'s pubkey
//
// Optional:
//
// voatNacl._signMessage(message, privatekey)
// voatNacl._verifyMessage(message, target_publickey)
// voatNacl._encryptMessage(message, target_publickey, privatekey)
// voatNacl._decryptMessage(message, nonce, target_publickey, privatekey)
//
// TODO: Add error checking.
//

var voatNacl = (function() {
  ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  //
  // GLOBAL PRIVATE VARIABLES
  //
  ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  var username = null;

  // keys for nacl sign/enc/decrypt
  var privatekey = null;
  var publickey = null;

  // keys for voat to encrypt the privkey in localStorage (should hide privkey from other scripts)
  var voat_privatekey = null;
  var voat_publickey = null;
  var voat_DH_privatekey = null;
  var voat_DH_publickey = null;

  ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  //
  // INITIALIZATION
  //
  ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  // Get Username
  api.get('/api/v1/system/user', function(result) {
    username = result.data;

    // Get Voat Privatekey
    state.get("voatnacl_voatprivatekey", function(result) {
      var _temp_privatekey = null;
      var _keys = null;

      if(!result.data) {
        // If no private key found, create all for voat
        _keys = nacl.sign.keyPair();
        state.save("voatnacl_voatprivatekey",'{"key":"'+nacl.util.encodeBase64(_keys.secretKey)+'"}',function(result) {
          if(!result.success)
            console.log("Failed to save voat private key to voat state");
        });
        voat_privatekey = _keys.secretKey;
      }
      else {
        // Take private key and generate the rest
        _keys = nacl.sign.keyPair.fromSecretKey((voat_privatekey = nacl.util.decodeBase64(result.data.key)));
      }
      voat_publickey = _keys.publicKey;
      voat_DH_publickey = ed2curve.convertPublicKey(voat_publickey);
      voat_DH_privatekey = ed2curve.convertSecretKey(voat_privatekey);

      // Load Secret Key from Local Storage
      if(!(_temp_privatekey=window.localStorage.getItem("voatnacl_" + username))) {
        // If not found, load from state
        state.get("voatnacl_encprivatekey", function(result) {
          var _enc = null;

          if(!result.data) {
              // If not found, create a key
              var _keys = nacl.sign.keyPair();

              // Save to Local Variables
              publickey = _keys.publicKey;
              privatekey = _keys.secretKey;
          }
          // Prompt User for Password
          while(!_enc) {
            _enc = prompt("Please enter your voatnacl password:");
          }
          if(!result.data) {
            // Encrypt Key
            var _encrypted = CryptoJS.AES.encrypt(nacl.util.encodeBase64(privatekey), _enc).toString();

            // Save Key to State
            state.save("voatnacl_encprivatekey",'{"key":"'+_encrypted+'"}',function(result) {
              if(!result.success)
                console.log("Failed to save encrypted private key to voat state");
            });

            // Save Public Key to Bio
            api.get('/api/v1/u/preferences',function(result) {
              var _bio=null;

              if(result.success) {
                _bio=result.data.bio;
                var _pattern=/(.+?(?=\$\$))\$\$\$[^\$]+\$\$\$/g;
                var _res=_pattern.exec(_bio);
                if(_res) {
                  if (_res.length>1) {
                    _bio = _res[1];
                  }
                }

                api.put('/api/v1/u/preferences',{"bio":_bio+' $$$'+nacl.util.encodeBase64(publickey)+'$$$'},function(result) {
                  if(!result.success)
                    console.log("Failed to save public key to bio");
                });
              }
            });

            // Encrypt Key with Voat Key
            var _nonce = nacl.randomBytes(nacl.box.nonceLength);
            var _voat_encrypted = nacl.box(nacl.util.decodeUTF8(nacl.util.encodeBase64(privatekey)),_nonce,voat_DH_publickey,voat_DH_privatekey);

            // Save Voat Encrypted Key to Local Storage
            window.localStorage.setItem("voatnacl_" + username,'{"key": "'+nacl.util.encodeBase64(_voat_encrypted)+'","nonce": "'+nacl.util.encodeBase64(_nonce)+'"}');            
          }
          else {
            // Decrypt Key
            var _decrypted = CryptoJS.AES.decrypt(result.data.key, _enc).toString(CryptoJS.enc.Utf8);
            var _nonce = nacl.randomBytes(nacl.box.nonceLength);
            var _keys = nacl.sign.keyPair.fromSecretKey(nacl.util.decodeBase64(_decrypted));

            // Save keys to memory
            publickey = _keys.publicKey;
            privatekey = nacl.util.decodeBase64(_decrypted);

            // Encrypt Key with Voat Key
            var _voat_encrypted = nacl.box(nacl.util.decodeUTF8(_decrypted),_nonce,voat_DH_publickey,voat_DH_privatekey);

            // Save Voat Encrypted Key to Local Storage
            window.localStorage.setItem("voatnacl_" + username,'{"key": "'+nacl.util.encodeBase64(_voat_encrypted)+'","nonce": "'+nacl.util.encodeBase64(_nonce)+'"}');
          }
        });
      }
      else {
        // Decrypt Key with Voat Key
        var _nonce = nacl.util.decodeBase64(JSON.parse(window.localStorage.getItem("voatnacl_"+username)).nonce);
        var _keys = nacl.sign.keyPair.fromSecretKey(nacl.util.decodeBase64(nacl.util.encodeUTF8(nacl.box.open(nacl.util.decodeBase64(JSON.parse(_temp_privatekey).key),_nonce,voat_DH_publickey,voat_DH_privatekey))));


        // Save keys to memory
        publickey = _keys.publicKey;
        privatekey = _keys.secretKey;
      }
    });
  });

  ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  //
  // PRIVATE UTILITY FUNCTIONS
  //
  ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  // purpose: decode a uint8array into a string
  // usage:   decoder.decode(uint8array)
  var decoder = new TextDecoder();

  // purpose: make a simple voat API get call as a promise
  var promiseApiGet = function(call) {
    return new Promise(function(resolve) {
      api.get(call,function(result) {
        if(result.success) {
          resolve(result.data);
        }
      });
    });
  }

  ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  //
  // RAW NACL FUNCTIONS FOR USE WITH ACTUAL PRIVATE OR PUBLiC KEYS
  //
  ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  // purpose: sign a message using a private key and return signature
  var _signMessage = function(msg, privkey) {
     return nacl.util.encodeBase64(nacl.sign(nacl.util.decodeUTF8(msg),privkey));
  }
  
  // purpose: verifies signature with pubkey and returns original message or null if it's not validly signed
  var _verifyMessage = function(msg, pubkey) {
    var _returnv = null;
 
    return ((_returnv = nacl.sign.open(nacl.util.decodeBase64(msg),nacl.util.decodeBase64(pubkey))) ? decoder.decode(_returnv) : null);
  }

  // purpose: encrypts and returns a voatnacl encrypted message in this format:
  // {"nonce":NONCE,"message":MESSAGE}
  var _encryptMessage = function(msg, pubkey, privkey) {
    var _nonce = nacl.randomBytes(nacl.box.nonceLength);
    var _target_DH_pubkey = ed2curve.convertPublicKey(nacl.util.decodeBase64(pubkey));
    
    return {
      "nonce":nacl.util.encodeBase64(_nonce),
      "message":nacl.util.encodeBase64(nacl.box(nacl.util.decodeUTF8(msg),_nonce,_target_DH_pubkey,ed2curve.convertSecretKey(privkey)))      
    }
  }

  // purpose: decrypts message with pubkey and returns decrypted message
  var _decryptMessage = function(msg, nonce, pubkey, privkey) {
    var _nonce = nacl.util.decodeBase64(nonce);
    var _msg = nacl.util.decodeBase64(msg);
    var _target_DH_pubkey = ed2curve.convertPublicKey(nacl.util.decodeBase64(pubkey));

    return decoder.decode(nacl.box.open(_msg,_nonce,_target_DH_pubkey, ed2curve.convertSecretKey(privkey)));
  }


  ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  //
  // PUBLIC PUBKEY SAVING FUNCTIONS
  //
  ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  // purpose: check if we have the user pubkey (true or false)
  var haveUserPubkey = function(user) {
     return (window.localStorage.getItem("voatnacl_pubkey_"+user) ? true : false);
  }

  // purpose: returns user's pubkey, or returns null
  var getUserPubkey = function(user) {
     return window.localStorage.getItem("voatnacl_pubkey_"+user);
  }

  // purpose: saves a user's pubkey and returns it
  var saveUserPubkey = async function(user) {
    if(!voatNacl.haveUserPubkey(user)) {
      var _n=null;
      var _x = await promiseApiGet('/api/v1/u/'+user+'/info').then(function(_y) {
        var _pattern=/\$\$\$([^$]+)\$\$\$/g;

        var _res=_pattern.exec(_y.bio);

        if(_res) {
          if (_res.length>1) {
            window.localStorage.setItem("voatnacl_pubkey_"+user,_res[1]);
            _n = _res[1];
          }
        }
      });
      return _n;
    }
    else
      return voatNacl.getUserPubkey(user);
  }

  ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  //
  // PUBLIC NACL FUNCTIONS FOR USE WITH VOAT USERNAMES
  //
  ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  // purpose: returns a voatnacl signed message signature.
  var signMessage = async function(msg) {
    return _signMessage(msg,privatekey);      
  }

  // purpose: verifies signed msg with username, returns words or null if it's invalidly signed
  var verifyMessage = async function(msg, user) {
    var _temp = null;
    if(!voatNacl.haveUserPubkey(user)) {
      await voatNacl.saveUserPubkey(user).then(function(value){
        _temp=value;
      });
      return _verifyMessage(msg,_temp);
    }
    else {
      return _verifyMessage(msg,voatNacl.getUserPubkey(user));
    }
  }

  // purpose: encrypts and reutrns a voatnacl encrypted message in this format:
  // {"nonce":NONCE,"message":MESSAGE}
  var encryptMessage = async function(msg, user) {
      var _temp = null;
      if(!voatNacl.haveUserPubkey(user)) {
        await voatNacl.saveUserPubkey(user).then(function(value){
          _temp=value;
        });
        return _encryptMessage(msg,_temp,privatekey);
      }
      else {
        return _encryptMessage(msg,voatNacl.getUserPubkey(user),privatekey);
      }
  }

  // purpose: Decrypts an encrypted msg with nonce by user
  var decryptMessage = async function(msg, nonce, user) {
    var _temp = null;
    if(!voatNacl.haveUserPubkey(user)) {
      await voatNacl.saveUserPubkey(user).then(function(value){
        _temp=value;
      });
      return _decryptMessage(msg, nonce,_temp,privatekey);
    }
    else {
      return _decryptMessage(msg, nonce,voatNacl.getUserPubkey(user),privatekey);
    }
  }
  
  return {
    haveUserPubkey: haveUserPubkey,
    getUserPubkey: getUserPubkey,
    saveUserPubkey: saveUserPubkey,
    /* */
    signMessage: signMessage,
    verifyMessage: verifyMessage,
    encryptMessage: encryptMessage,
    decryptMessage: decryptMessage,
    /* */
    _signMessage: _signMessage,
    _verifyMessage: _verifyMessage,
    _encryptMessage: _encryptMessage,
    _decryptMessage: _decryptMessage
  }
})();

return {
  CryptoJS: CryptoJS,
  voatNacl: voatNacl
}

