from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
import pgpy
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm
from pgpy import PGPKey, PGPMessage
import secrets
from dateutil.parser import parse
import datetime
import json
import requests
import base64
import subprocess
import os
import random
import string
import ntplib

def generate_keys(key_strength = 4096, failsafe = False):
    '''
    This function creates a public and private key based on PGP
    protocols.

    Parameters
    ----------
    key_strength int
        The cryptographic security level in units of bits.
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
    key.protect(PRIVATE_KEY_PASS, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)

    # private and public key
    private_key = str(key)
    public_key = str(key.pubkey)

    if failsafe :
        print("PGP Private Key:\n", private_key)
        print("PGP Private Key Password:\n", private_key_pass)
        print("PGP Public Key:\n", public_key)

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
    encrypted_string = bytes(PGPKey.from_blob(PUBLIC_KEY)[0].encrypt(message))
    return encrypted_string

def decrypt(message):
    '''
    Given a PGP message, this function will try to decrypt
    based on the private key global variable
    '''
    # decrypt using private key
    private_key_test = PGPKey.from_blob(PRIVATE_KEY)[0] # reads in from string format
    with private_key_test.unlock(PRIVATE_KEY_PASS) as unlocked_private_key :
        result = unlocked_private_key.decrypt(PGPMessage.from_blob(message))
    unencrypted_string = result.message
    print(unencrypted_string)
    return unencrypted_string

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

def get_config(key):
    '''
    From the CSV credentials file, we will return the corresponding
    value in the row where the key is found in the first column.
    '''
    path = os.getenv('KEYS_JSON')
    if path :
        with open(path, 'r') as file:
            configs = json.load(file)
        return configs.get(key)
    else :
        return False

def version():
    try:
        git_dir = get_config("GIT_DIR")
        if git_dir:
            commit_hash = subprocess.check_output(
                ["git", "--git-dir", f"{git_dir}/.git", "rev-parse", "--short", "HEAD"]
            )
            return commit_hash.decode("utf-8").strip()
        else:
            print("The git directory is not configured.")
    except Exception as e:
        print(str(e))
    # default version if something didn't work
    return "development"

# scroll down to the bottom for initialization
# run with `uvicorn main:app --reload --host 0.0.0.0 --port 1337`
app = FastAPI(docs_url="/",
    title="time_crypt Service",
    description="A RESTful API service to generate and unlock time-sensitive passcodes.",
    version=version()
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],  # Set the allowed origins, use ['*'] to allow all origins
    allow_credentials=True,  # Set to True if you want to allow sending or receiving cookies
    allow_methods=['*'],  # Set the allowed HTTP methods, use ['*'] to allow all methods
    allow_headers=['*']  # Set the allowed HTTP headers, use ['*'] to allow all headers
)

@app.get("/test")
def hello_world():
    '''
    Please reference https://fastapi.tiangolo.com/
    '''
    return "Hello, world! Please visit the /docs directory for documentation and a demo."

@app.get("/create")
def create(request: Request, expire=None, minutes=None, length=8, utc_offset=-5):
    '''
    This creates a passcode for the API. Timezone 
    can be specified by including it in the expiry
    parameter. The utc_offset is based on time_crypt
    deployments usually in eastern time, so adjust
    as needed.
    
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
    email string
        (Optional) This will email just the key to 
        the provided email.
    length integer
        (Optional) By default, it is 8 but we can 
        configure the number of digits in the passcode.
    utc_offset integer
        (Optional) The UTC offset to create the time
        aware expiration. By default, it's set to ET
    request Request
        The object to access the request directly.
    '''
    # we construct the time data for the lock
    if minutes : # user specifies an amount of time
        expire_time = datetime.datetime.now() + datetime.timedelta(minutes = int(minutes))
    else : # user specifies a time to expire
        expire_time = parse(expire)
    # set timezone if not specified in expire string or if minutes are passed
    if expire_time.tzinfo is None:
        expire_time = expire_time.replace(
            tzinfo=datetime.timezone(datetime.timedelta(hours=int(utc_offset))))
    
    # generate a passcode
    passcode = ''.join([str(secrets.randbelow(10)) for i in range(int(length))])
    key = lock_data(expire_time, passcode)
    # convert to base64 to avoid encoding problems
    key = base64.b64encode(key).decode("ascii")
    
    return {
        "passcode" : passcode,
        "expires_at" : expire_time,
        "key" : key
    }

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
    key = base64.b64decode(key.encode("ascii"))
    decrypted = decrypt(key).split(" ")
    decrypted_time = decrypted[0]
    decrypted_passcode = decrypted[1]
    # check if it can be unlocked. both should be timezone-aware
    # note that python converts these times to UTC internally for comparison automatically
    if parse(decrypted_time) <= timestamp() :
        return decrypted_passcode
    else :
        return f"Expires on {decrypted_time}"

def generate_random_string(min_length=15, max_length=60):
    length = random.randint(min_length, max_length)
    characters = string.ascii_letters + string.digits
    random_string = ''.join(random.choice(characters) for _ in range(length))
    return random_string

def timestamp(ntp_server='pool.ntp.org', time_zone=datetime.timezone.utc):
    '''
    Gets the current time from NTP server or from system if OFFLINE parameter set

    Parameters
    ----------
    ntp_server str
        The URL for the NTP server. Note that the function utilizes version 3 for max
        compatibility
    time_zone datetime.datetime.tz
        The timezone in a datetime object for the ntp_server URL. While many NTP 
        servers return the time in UTC, some do it in their local time
    '''
    # use system time if on offline mode, otherwise use NTP server
    if get_config('OFFLINE'):
        return datetime.datetime.now()
    else: # get time from NTP server
        client = ntplib.NTPClient()
        current_time = client.request(ntp_server, version=3).tx_time # unix format
        return datetime.datetime.fromtimestamp(current_time, time_zone)

# globals and default configurations
PUBLIC_KEY = False
PRIVATE_KEY = False
PRIVATE_KEY_PASS = get_config('TIME_CRYPT_PASS')
if not PRIVATE_KEY_PASS:
    PRIVATE_KEY_PASS = generate_random_string()
set_keys()
