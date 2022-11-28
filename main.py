from fastapi import FastAPI, Request
import pgpy
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm
from pgpy import PGPKey, PGPMessage
import secrets
from dateutil.parser import parse
import datetime
import requests
import json

# scroll down to the bottom for initialization
# run with `uvicorn main:app --reload --host 0.0.0.0 --port 1337`
app = FastAPI(docs_url="/")

# globals
PUBLIC_KEY = False
PRIVATE_KEY = False
DEFAULT_PASS = 'j5&45MZsF0v&'
IP_TABLE = {}

@app.get("/test")
def hello_world():
    '''
    Please reference https://fastapi.tiangolo.com/
    '''
    return {"Hello": "World"}

@app.get("/create")
def create(request: Request, expire=None, minutes=None, log=False, length=8):
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
    request Request
        The object to access the request directly.
    '''
    # we construct the time data for the lock
    if minutes : # user specifies an amount of time
        expire_time = datetime.datetime.now() + datetime.timedelta(minutes = int(minutes))
    else : # user specifies a time to expire
        expire_time = parse(expire)
    
    # generate a passcode
    passcode = ''.join([str(secrets.randbelow(10)) for i in range(int(length))])
    key = lock_data(expire_time, passcode)

    # add to ip table
    if log :
        ip = request.client.host
        global IP_TABLE
        IP_TABLE[ip] = {
            "expires_at" : expire_time,
            "key" : key
        }

    return {
        "passcode" : passcode,
        "expires_at" : expire_time,
        "key" : key
    }

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
    data = f"{expire_time.isoformat()} {passcode}"
    key = encrypt(data) # encrypt it using PGP
    return key

@app.get("/unlock")
def unlock(key: str) :
    '''
    Based on the key returned from the create API,
    this API unlocks it.

    Parameters
    ----------
    key string
        Encoded public key message with the time and
        passcode in it.

    Returns
    -------
    string
        The passcode if there is one or an associated
        error message
    '''
    decrypted = decrypt(pgpy.PGPMessage.from_blob(bytes(key, encoding='utf8'))).split(" ")
    decrypted_time = decrypted[0]
    decrypted_passcode = decrypted[1]
    # check if it can be unlocked
    if parse(decrypted_time) <= datetime.datetime.now() :
        return decrypted_passcode
    else :
        return f"Expires on {decrypted_time}"

@app.get("/ip_unlock")
def ip_unlock(request: Request):
    '''
    Checks IP of request and returns the status
    of the keys
    '''
    return IP_TABLE.get(request.client.host, "No IP entries found")

def generate_keys(key_strength = 4096, failsafe = False):
    '''
    This function creates a public and private key based on PGP
    protocols.

    Parameters
    ----------
    failsafe bool
        The failsafe prints the private and public pgp key to the console.
        This is disabled by default because it leads to an exploit that
        breaks end-to-end encryption.

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
    key.protect(DEFAULT_PASS, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)

    # private and public key
    private_key = str(key)
    public_key = str(key.pubkey)

    if failsafe :
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
    global PUBLIC_KEY
    global PRIVATE_KEY

    keys = generate_keys()

    PUBLIC_KEY = keys['public_key']
    PRIVATE_KEY = keys['private_key']

def encrypt(message):
    '''
    Encrypts the message using the global public key
    '''
    message = pgpy.PGPMessage.new(message)
    encrypted_string = str(PGPKey.from_blob(PUBLIC_KEY)[0].encrypt(message))
    print(encrypted_string)
    return encrypted_string

def decrypt(message):
    '''
    Given a PGP message, this function will try to decrypt
    based on the private key global variable
    '''
    # decrypt using private key
    private_key_test = PGPKey.from_blob(PRIVATE_KEY)[0] # reads in from string format
    with private_key_test.unlock(DEFAULT_PASS) as unlocked_private_key :
        result = unlocked_private_key.decrypt(PGPMessage.from_blob(message))
    unencrypted_string = result.message
    print(unencrypted_string)
    return unencrypted_string

# set globals
set_keys()
