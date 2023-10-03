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
import smtplib
from email.message import EmailMessage

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
        return None

def email_key(key, expire, address):
    '''
    Emails the key using the SMTP credentials provided.
    '''
    msg = EmailMessage()
    msg.set_content(key)
    msg['Subject'] = f'time_cyrpt: Expires at {expire}'
    msg['From'] = get_config('from')
    msg['To'] = address
    try:
        server = smtplib.SMTP(get_config('HOST'), get_config('PORT'))
        server.ehlo()
        server.starttls()
        #stmplib docs recommend calling ehlo() before & after starttls()
        server.ehlo()
        server.login(get_config('USERNAME_SMTP'), get_config('PASSWORD_SMTP'))
        server.send_message(msg)
        server.close()
    # Display an error message if something goes wrong.
    except Exception as e:
        print("Error: ", e)

def version():
    try:
        git_dir = get_config("GIT_DIR")
        if git_dir:
            commit_hash = subprocess.check_output(
                ["git", "--git-dir", f"{git_dir}/.git", "rev-parse", "--short", "HEAD"]
            )
            return commit_hash.decode("utf-8").strip()
        else:
            print("Could'nt find the git directory.")
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

# globals and default configurations
PUBLIC_KEY = False
PRIVATE_KEY = False
DEFAULT_PASS = get_config('TIME_CRYPT_PASS')
if not DEFAULT_PASS : # set default password
    DEFAULT_PASS = 'j5&45MZsF0v&'

@app.get("/test")
def hello_world():
    '''
    Please reference https://fastapi.tiangolo.com/
    '''
    return "Hello, world! Please visit the /docs directory for documentation and a demo."

@app.get("/create")
def create(request: Request, expire=None, minutes=None, email=False, length=8):
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
    email string
        (Optional) This will email just the key to 
        the provided email.
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
    # convert to base64 to avoid encoding problems
    key = base64.b64encode(key).decode("ascii")

    # add to ip table
    if email :
        email_key(key, expire_time, email)
    
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
    key = base64.b64decode(key.encode("ascii"))
    decrypted = decrypt(key).split(" ")
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
    encrypted_string = bytes(PGPKey.from_blob(PUBLIC_KEY)[0].encrypt(message))
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
