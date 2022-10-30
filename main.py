from fastapi import FastAPI
import pgpy
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm
from pgpy import PGPKey, PGPMessage

# run with `uvicorn main:app --reload`
app = FastAPI(docs_url="/")

# globals
public_key = False
private_key = False
default_pass = 'j5&45MZsF0v&'

@app.get("/test")
def read_root():
    '''
    Please reference eference https://fastapi.tiangolo.com/
    '''
    return {"Hello": "World"}

def generate_keys(key_strength = 4096):
    '''
    This function creates a public and private key based on PGP
    protocols.

    References
    ----------
    - https://github.com/shakjaguar/SimplePGP/issues/1#issuecomment-772716884
    '''

    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, key_strength)
    key.add_uid(pgpy.PGPUID.new('admin'),
        usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
        hashes=[HashAlgorithm.SHA256, HashAlgorithm.SHA384, HashAlgorithm.SHA512, HashAlgorithm.SHA224],
        ciphers=[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES192, SymmetricKeyAlgorithm.AES128],
        compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.BZ2, CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed])

    # password protect private key
    key.protect(default_pass, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)

    # private and public key
    private_key = str(key)
    public_key = str(key.pubkey)
    print(private_key)
    print(public_key)

    return {
        'public_key' : public_key,
        'private_key' : private_key
    }

def set_keys():
    '''
    Set the keys as globals
    '''
    global public_key
    global private_key

    keys = generate_keys()

    public_key = keys['public_key']
    private_key = keys['private_key']

def encrypt(message):
    '''
    Encrypts the message using the global public key
    '''
    message = pgpy.PGPMessage.new(message)
    encrypted_string = str(PGPKey.from_blob(public_key)[0].encrypt(message))
    print(encrypted_string)
    return encrypted_string

def decrypt(message):
    '''
    Given a PGP message, this function will try to decrypt
    based on the private key global variable
    '''
    # decrypt using private key
    private_key_test = PGPKey.from_blob(private_key)[0] # reads in from string format
    with private_key_test.unlock(default_pass) as unlocked_private_key :
        result = unlocked_private_key.decrypt(PGPMessage.from_blob(message))
    unencrypted_string = result.message
    print(unencrypted_string)
    return unencrypted_string
