// voatNacl v0.1.2-alpha
//
// Use SaltShaker (nacl, aes) to encrypt/decrypt and sign/verify messages and posts on voat.co
//
// Copyright (c) 2019 realrasengan
//
// This is free and unencumbered software released into the public domain.
//
// Anyone is free to copy, modify, publish, use, compile, sell, or
// distribute this software, either in source code form or as a compiled
// binary, for any purpose, commercial or non-commercial, and by any
// means.
//
// In jurisdictions that recognize copyright laws, the author or authors
// of this software dedicate any and all copyright interest in the
// software to the public domain. We make this dedication for the benefit
// of the public at large and to the detriment of our heirs and
// successors. We intend this dedication to be an overt act of
// relinquishment in perpetuity of all present and future rights to this
// software under copyright law.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.
//
// For more information, please refer to <http://unlicense.org>
//
// THIS SOFTWARE IS UNAUDITED.  USE AT YOUR OWN RISK.

(function(voatNacl)  {

  var username = null;    // current user
  var keys = null;        // current user's keys
  var voat_keys = null;   // voat's keys for current user

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
      if(!result.data) {
        // If no private key found create keypair and save
        voat_keys = SaltShaker.create();
        state.save("voatnacl_voatprivatekey",'{"key":"'+voat_keys.privatekey+'"}',function(result) {
          if(!result.success)
            console.log("Failed to save voat private key to voat state");
        });
      }
      else {
        // else create keys from previous private key
        voat_keys = SaltShaker.create(result.data.key);
      }

      // Load Secret Key from Local Storage
      var _temp_privatekey = null;
      if(!(_temp_privatekey=window.localStorage.getItem("voatnacl_" + username))) {
        // If not found, load from state
        state.get("voatnacl_encprivatekey", function(result) {
          var _enc = null;

          if(!result.data) {
              // If not found, create a key
              keys = SaltShaker.create();
          }
          // Prompt User for Password
          while(!_enc) {
            _enc = prompt("Please enter your voatnacl password:");
          }
          if(!result.data) {
            // Encrypt Key with AES symmetric key (password)
            var _encrypted = SaltShaker.AESencrypt(keys.privatekey, _enc);

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

                api.put('/api/v1/u/preferences',{"bio":_bio+' $$$'+keys.publickey+'$$$'},function(result) {
                  if(!result.success)
                    console.log("Failed to save public key to bio");
                });
              }
            });
            // Save Voat Encrypted Key to Local Storage
            window.localStorage.setItem("voatnacl_" + username, JSON.stringify(SaltShaker.encrypt(keys.privatekey, voat_keys.publickey, voat_keys.privatekey)));            
          }
          else {
            // Decrypt Key and recreate key pair
            keys = SaltShaker.create(SaltShaker.AESdecrypt(result.data.key, _enc));

            // Save Voat Encrypted Key to Local Storage
            window.localStorage.setItem("voatnacl_" + username, JSON.stringify(SaltShaker.encrypt(keys.privatekey ,voat_keys.publickey,voat_keys.privatekey)));
          }
        });
      }
      else {
        // Decrypt Key with Voat Key and regenerate pubkey pair
        keys = SaltShaker.create(SaltShaker.decrypt(JSON.parse(_temp_privatekey).message, JSON.parse(window.localStorage.getItem("voatnacl_"+username)).nonce, voat_keys.publickey, voat_keys.privatekey));
      }
    });
  });

  
  
  ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  //
  // PRIVATE FUNCTIONS
  //
  ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  // Function:  promiseApiGet
  // Purpose:   Performs a GET on the voat API in promisary form
  // Returns:   It returns a promise with the result data.
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
  // PUBLIC FUNCTIONS
  //
  ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  // Function:  haveUserPubkey
  // Purpose:   check if we have the user's pubkey
  // Returns:   true if we have it or false
  voatNacl.haveUserPubkey = function(user) {
    return (window.localStorage.getItem("voatnacl_pubkey_"+user) ? true : false);
  }

  // Function:  getUserPubkey
  // Purpose:   gets a user's pubkey from voat if we don't have it or from storage
  // Returns:   the user's pubkey
  voatNacl.getUserPubkey = async function(user) {
    if(!voatNacl.haveUserPubkey(user)) {
      var _pubkey=null;
      await promiseApiGet('/api/v1/u/'+user+'/info').then(function(_result) {
        var _pattern=/\$\$\$([^$]+)\$\$\$/g;
        var _res=_pattern.exec(_result.bio);
        if(_res) {
          if (_res.length>1) {
            window.localStorage.setItem("voatnacl_pubkey_"+user,_res[1]);
            _pubkey = _res[1];
          }
        }
      });
      return _pubkey;
    }
    else
      return window.localStorage.getItem("voatnacl_pubkey_"+user);
  }

  // Function:  sign
  // Purpose:   sign a msg
  // Returns:   a signature
  voatNacl.sign = async function(msg) {
    return SaltShaker.sign(msg,keys.privatekey);      
  }

  // Function:  verify
  // Purpose:   verify a signed msg from a user
  // Returns:   the message or null
  voatNacl.verify = async function(msg, user) {
    var _temp = null;
    await voatNacl.getUserPubkey(user).then(function(value){
      _temp=value;
    });
    return SaltShaker.verify(msg,_temp);
  }

  // Function: encrypt
  // Purpose:  encrypt's a msg with user's pubkey
  // Returns:  json object with {"nonce":NONCE,"message":ENCRYPTED-MESSAGE}
  voatNacl.encrypt = async function(msg, user) {
    var _temp = null;
    await voatNacl.getUserPubkey(user).then(function(value){
      _temp=value;
    });
    return SaltShaker.encrypt(msg,_temp,keys.privatekey);
  }

  // Function: decrypt
  // Purpose:  decrypt's an encrypted msg with nonce from user
  // Returns:  The decrypted msg
  voatNacl.decrypt = async function(msg, nonce, user) {
    var _temp = null;
    await voatNacl.getUserPubkey(user).then(function(value){
      _temp=value;
    });
    return SaltShaker.decrypt(msg, nonce,_temp,keys.privatekey);
  }

})(typeof module !== 'undefined' && module.exports ? module.exports : (self.voatNacl = self.voatNacl || {}));
