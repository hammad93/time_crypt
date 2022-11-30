# time_crypt
A cryptographic function and enables decryption based on a timer or other specified time.

## Link

http://198.57.44.233:1337/

## Use Case
There is a secret you want exposed only after a certain amount of time or at an exact date and time. You do not want yourself or anyone else to know this secret until we have reached this time-based requirement.

## Method
We create a web based SaaS where we create a public and private key. Secrets are encrypted and the SaaS decrypts it based on stored private key as well as the valid timestamp.

The respository is where this method is defined.

## Endpoints

### `create`
Generates a new passcode at the specified time by encoding the passcode and the expiry time into a new PGP message utilizing the SaaS's private key. This returns the PGP message that the user can save. Note that IP logging and unlock must be turned on.

### `unlock`
Manually check if the message generated can be unlocked based on time. If it is, return the passcode.

### `ip_unlocked`
Returns passcodes that are unlocked, or automatically decrypted based on time, by utilizing a user's internet address or IP.

### `locked`
Returns currently locked passcodes.

## Install
The software runs on Python 3. All other requirements are in the following code block that can be copy-pasted into a requirements.txt file.

```requirements.txt
fastapi
"uvicorn[standard]"
pgpy
dateutil
python-dateutil --upgrade
requests
```


## Quickstart

This overviews how we can utilize the API in the real-world use case that the algorithm was made for. The requirements are that this algorithm works regardless of the padlock technologies. Often, manufacturers of time-lock mechanisms make low-quality physical locks. Even if they improved, it may not be as effective against lock-picking compared to heavy-duty padlocks. Here, we present a solution that combines the two. We give the user a combination to put into multiple combination padlocks that is meant to be forgotten. If the user remembers, they simply request a new random combination. The combination is made up of 8 characters or digits. This means that this algorithm can be reused for many types of combination padlock technology in the past or present without additional costs.

1. Generate a new code and input lock time. 
  - Save the cryptographic message. The SaaS will save a .txt file with the message from your web browser.
  - The application will have a setting to enable saving the passcode to your exposed IP address, it is off by default.
2. Enter the code into your padlock(s) and lock the safe.
3. Check the status of the lock and unlock time. All time unlocked codes will automatically be exposed.
  - To decrypt from an anonymous source, the SaaS can read the message saved in step 1 and return if it's past the lock time.

Although the number of digits can be configured, the 8 digits that were meant to be "forgotten" is based on Miller's law that humans are able to remember about 7, plus or minus 2, objects in their short-term memory. 8 digits were also chosen because of the lack of availability of commerical locks and safes with more than 8 digits for their unlock combinations. 
