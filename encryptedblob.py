import base64
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
import imexceptions
import os
import hmac  # Import hmac module for HMAC functionality
from Crypto.Hash import SHA256  # Import SHA-256 hash function from PyCryptodome

class EncryptedBlob:

    # the constructor
    def __init__(self, plaintext=None, confkey=None, authkey=None): 
        self.plaintext = plaintext
        self.ivBase64 = None
        self.ciphertextBase64 = None
        self.macBase64 = None

        if plaintext is not None:
            self.ivBase64, self.ciphertextBase64, self.macBase64 = self.encryptThenMAC(confkey, authkey, plaintext)



    # encrypts the plaintext and adds a SHA256-based HMAC
    # using an encrypt-then-MAC solution
    def encryptThenMAC(self,confkey,authkey,plaintext):
        # TODO: MODIFY THE CODE BELOW TO ACTUALLY ENCRYPT 
        # AND GENERATE A SHA256-BASED HMAC BASED ON THE 
        # confkey AND authkey

        # first, we convert the passed keys to byte arrays using the bytes function
        confkey_bytes = bytes(confkey, 'ascii')
        authkey_bytes = bytes(authkey, 'ascii')

        # now, we generate some random 16-byte IV for the AES in CBC mode stuff
        iv = os.urandom(16)

        # pad the plaintext to make AES happy
        plaintextPadded = pad(bytes(plaintext,'utf-8'),16) 

        # now we create an AES cipher object that will perform encryption using CBC mode
        cipher = AES.new(confkey_bytes, AES.MODE_CBC, iv)

        # now we are actually encryppting the padded plaintext using AES-CBC
        ciphertext = cipher.encrypt(plaintextPadded)

        # Compute HMAC-SHA256 for authentication
        hmac_obj = hmac.new(authkey_bytes, iv + ciphertext, SHA256)
        mac = hmac_obj.digest()

        # DON'T CHANGE THE BELOW.
        # What we're doing here is converting the iv, ciphertext,
        # and mac (which are all in bytes) to base64 encoding, so that it 
        # can be part of the JSON EncryptedIM object
        ivBase64 = base64.b64encode(iv).decode("utf-8") 
        ciphertextBase64 = base64.b64encode(ciphertext).decode("utf-8") 
        macBase64 = base64.b64encode(mac).decode("utf-8") 
        return ivBase64, ciphertextBase64, macBase64


    def decryptAndVerify(self,confkey,authkey,ivBase64,ciphertextBase64,macBase64):
        # up here is decoding the base 64 encoded values
        iv = base64.b64decode(ivBase64)
        ciphertext = base64.b64decode(ciphertextBase64)
        mac = base64.b64decode(macBase64)
        
        # TODO: MODIFY THE CODE BELOW TO ACTUALLY DECRYPT
        # IF IT DOESN'T DECRYPT, YOU NEED TO RAISE A 
        # FailedDecryptionError EXCEPTION

        # TODO: hint: in encryptThenMAC, I padded the plaintext.  You'll
        # need to unpad it.
        # See https://pycryptodome.readthedocs.io/en/v3.11.0/src/util/util.html#crypto-util-padding-module

        # so, this next line is definitely wrong.  :)
        #self.plaintext = "It's a wonderful day in the neighborhood."
        
        # TODO: DON'T FORGET TO VERIFY THE MAC!!!
        # IF IT DOESN'T VERIFY, YOU NEED TO RAISE A
        # FailedAuthenticationError EXCEPTION

        # raise imexceptions.FailedAuthenticationError("ruh oh!")

        # Convert keys to byte arrays
        confkey_bytes = bytes(confkey, 'ascii')
        authkey_bytes = bytes(authkey, 'ascii')

        # Recompute HMAC and verify
        hmac_obj = hmac.new(authkey_bytes, iv + ciphertext, SHA256)
        computed_mac = hmac_obj.digest()
        
        # this is the raising exceptions part I commented above from OG code
        if not hmac.compare_digest(mac, computed_mac):
            raise imexceptions.FailedAuthenticationError("MAC verification failed!")

        # Decrypt using AES-CBC
        cipher = AES.new(confkey_bytes, AES.MODE_CBC, iv)
        plaintextPadded = cipher.decrypt(ciphertext)

        try:
            # Remove padding
            plaintext = unpad(plaintextPadded, AES.block_size).decode("utf-8")
        except ValueError:
            raise imexceptions.FailedDecryptionError("Decryption failed!")

        return self.plaintext
