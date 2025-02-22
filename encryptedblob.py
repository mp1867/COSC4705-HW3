import base64
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import imexceptions


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
        # TODO: MODIFY THE CODE BELOW TO ACTUALLY ENCRYPT AND GENERATE A SHA256-BASED HMAC BASED ON THE confkey AND authkey

        # pad the plaintext to make AES happy
        plaintextPadded = pad(bytes(plaintext,'utf-8'),16) 

        #ciphertext = plaintextPadded  # definitely change this. :)
        cipher = AES.new(confkey, AES.MODE_CBC)

        #iv = bytes([0x00, 0x00, 0x00, 0x00])  # and this too!
        # retrieve the randomly generated IV from the cipher object
        iv = cipher.iv

        # encrypt the padded plain text
        ciphertext = cipher.encrypt(plaintextPadded)

        #mac = bytes([0x00, 0x00, 0x00, 0x00]) # and this too!
        # now we generate HMAC manually using SHA-256 from the modules
        mac_input = iv + ciphertext

        # compute SHA-hash 
        sha256_hasher = SHA256.new()
        sha256_hasher.update(authkey)  # Use authkey as the HMAC key
        sha256_hasher.update(mac_input)  # Add the IV + Ciphertext as the message
        mac = sha256_hasher.digest()  # Get the final digest

        # DON'T CHANGE THE BELOW.
        # What we're doing here is converting the iv, ciphertext,
        # and mac (which are all in bytes) to base64 encoding, so that it 
        # can be part of the JSON EncryptedIM object
        ivBase64 = base64.b64encode(iv).decode("utf-8") 
        ciphertextBase64 = base64.b64encode(ciphertext).decode("utf-8") 
        macBase64 = base64.b64encode(mac).decode("utf-8") 
        return ivBase64, ciphertextBase64, macBase64


    def decryptAndVerify(self,confkey,authkey,ivBase64,ciphertextBase64,macBase64):
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

        # after we decode the base64 vals, we need to recompute the MAC to verify integrity
        mac_input = iv + ciphertext
        sha256_hasher = SHA256.new()
        sha256_hasher.update(authkey)  # Use authkey as HMAC key
        sha256_hasher.update(mac_input)  # Add IV + Ciphertext as message
        computed_mac = sha256_hasher.digest()  # Compute digest

        # now we can verify the MAC
        if computed_mac != mac:
            raise imexceptions.FailedAuthenticationError("MAC verification failed!")

        # Step 4: Decrypt ciphertext using AES-256-CBC
        cipher = AES.new(confkey, AES.MODE_CBC, iv)
        try:
            plaintext_padded = cipher.decrypt(ciphertext)  # Decrypt
            plaintext = unpad(plaintext_padded, AES.block_size)  # Remove padding
        except ValueError:  # Raised if padding is incorrect (decryption failure)
            raise imexceptions.FailedDecryptionError("Decryption failed or invalid padding!")

        # Step 5: Return plaintext as a UTF-8 string
        return plaintext.decode("utf-8")
    
        #raise imexceptions.FailedAuthenticationError("ruh oh!")
        
        #return self.plaintext
