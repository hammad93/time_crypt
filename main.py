from fastapi import FastAPI
import pgpy
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm
from pgpy import PGPKey, PGPMessage
import secrets
from dateutil.parser import parse
import datetime

# scroll down to the bottom for initialization

# globals
public_key = False
private_key = False
default_pass = 'j5&45MZsF0v&'

@app.get("/test")
def read_root():
    '''
    Please reference https://fastapi.tiangolo.com/
    '''
    return {"Hello": "World"}

def create(expire, minutes = None, log = False, length = 8):
    '''
    This creates a passcode for the API. Timezone 
    will be interpreted from the IP of the request.
    
    Parameters
    ----------
    expire string
        A string to interpret a timestamp for when
        the passcode should expire.
    minutes string
        (Optional) Alternatively to expiration, a 
        user can input a length of time to create.
        The current time used will be the timetamp
        from the request.
    log boolean
        (Optional) Specifies if we log the passcode
        and automatically unlock it based on the 
        IP of the request.
    length integer
        (Optional) By default, it is 8 but we can 
        configure the number of digits in the passcode.
    '''
    # the unlock data structure is at a timestamp
    # so we construct it here
    if minutes : # user specifies an amount of time to expire from the request
        # keep this command earlier in the method to ensure low latency
        request_timestamp = datetime.datetime.now() # TODO
        expire_time = request_timestamp + datetime.timedelta(minutes = minutes)
    else : # user specifies a time to expire
        expire_time = parse(expire)
    # generate a passcode
    passcode = ''.join([secrets.randbelow(10) for i in range(length)])
    key = lock_data(expire_time, passcode)

def lock_data(expire_time, passcode) :
    '''
    Parameters
    ----------
    expire_time datetime
        Will be transformed to a ISO8601 
        timestamp and saved in the key
        message.
    passcode string
        The randomly generated passcode. Please
        do not have any spaces in the passcode.

    Returns
    -------
    string
        The encrypted string based on the input.
    '''
    data = f"{expire_time.iso_format()} {passcode}"
    key = encrypt(data) # encrypt it using PGP
    return key

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

# set globals
set_keys()
# run with `uvicorn main:app --reload`
app = FastAPI(docs_url="/")