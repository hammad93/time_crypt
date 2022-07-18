# time_crypt
A cryptographic function and enables decryption based on a timer or other specified time.

## Use Case
There is a secret you want exposed only after a certain amount of time or at an exact date and time. You do not want yourself or anyone else to know this secret until we have reached this time-based requirements.

## Method
We can define an oracle of time, in this case an API to Microsoft's time gateway, and use their SSL certificate to authenticate the validity of the time. 
