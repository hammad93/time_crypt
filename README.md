# time_crypt
A cryptographic function and enables decryption based on a timer or other specified time.

## Link

_The experimental deployment is still in process_

## Use Case
There is a secret you want exposed only after a certain amount of time or at an exact date and time. You do not want yourself or anyone else to know this secret until we have reached this time-based requirement.

## Method
We can define an oracle of time and use their SSL certificate to authenticate the validity of the time.

We then create a web based SaaS where we create a public and private key. Secrets are encrypted and the SaaS decrypts it based on stored private key as well as the valid timestamp.

The respository is where this method is defined.

## Quickstart

This overviews how we can utilize the API in the real-world use case that the algorithm was made for. The requirements are that this algorithm works regardless of the padlock technologies. Often, manufacturers of time-lock mechanisms make low-quality physical locks. Even if they improved, it may not be as effective against lock-picking compared to heavy-duty padlocks. Here, we present a solution that combines the two. We give the user a combination to put into multiple combination padlocks that is meant to be forgotten. If the user remembers, they simply request a new random combination. The combination is made up of 8 characters or digits. This means that this algorithm can be reused for any time of combination padlock technology in the past or the future irrespective of the hardware.

1. Generate a new code and input lock time. The system will save the code to your exposed IP address by default or you can enter in an email address.
2. Enter the code into your padlock(s) and lock the safe.
3. Check the status of the lock and unlock time. All time unlocked codes will automatically be exposed.

The 8 digits that were meant to be "forgotten" is based on Miller's law that humans are able to remember about 7, plus or minus 2, objects in their short-term memory. 8 digits were also chosen because of the lack of availability of commerical locks and safes with more than 8 digits for their unlock combinations. If your memory is much better than most, we recommend some tequila before this procedure. 
