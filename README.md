# time_crypt
A cryptographic function that enables decryption based on length of time or other specified time.

## Table of Contents

- [Use Case](#use-case)
- [Quickstart](#quickstart)  
- [Endpoints](#endpoints)  
  - [`test`](#test)  
  - [`create`](#create)  
  - [`unlock`](#unlock)  
- [Quick Install](#quick-install)  
  - [Python](#python)  
- [Configuration](#configuration)  
- [Production Install](#production-install)  
  - [Setting up timecrypt.service in Ubuntu](#setting-up-timecryptservice-in-ubuntu)  
    - [1. Save the Service File](#1-save-the-service-file)  
    - [2. Move the Service File to systemd Directory](#2-move-the-service-file-to-systemd-directory)  
    - [3. Ensure Uvicorn is Accessible](#3-ensure-uvicorn-is-accessible)  
    - [4. Reload systemd](#4-reload-systemd)  
    - [5. Start and Enable the Service](#5-start-and-enable-the-service)  
    - [6. Check the Service Status](#6-check-the-service-status)  
  - [Maintaining Uptime](#maintaining-uptime)  
- [Notes](#notes)  
- [User interface](#user-interface)


## Use Case

There is a secret you want exposed only after a certain amount of time or at an exact date and time. You do not want yourself or anyone else to know this secret until we have reached this time-based requirement. Often, manufacturers of time-lock mechanisms make low-quality physical locks. Even if they improved, it may not be as effective against lock-picking compared to heavy-duty padlocks. Here, we present a solution that combines the two. We give the user a combination to put into multiple combination padlocks that is meant to be forgotten. If the user remembers, they can request a new random combination.

## Quickstart

This section outlines the 12 step program to create real-world time sensitive locks. The prerequisites include access to a physical safe with at least 8 digit combination. The time_crypt application must also be properly installed with Python on Windows, Mac, Linux, and other supported operating systems. The use case example is with a one digital combination safe featuring a 8 digit lock but longer combinations are achievable with multiple combination padlocks and a group lock box.

1. Prepare the lock(s) by reading the instructions on to set a new combination (8 digits) to ensure the new combination will be entered accurately.
2. Place your time-sensitive items into the safe, lock box, etc.
3. Access the time_crypt application through the web user interface.
4. Enter the time (such as "January 1st, 2026 12am") for when you would like the combination to be available or the expiry time. Natural language or standard timestamps are supported.
5. Record only the key, a long string of only numbers and letters, but never the combination. The key can be entered into time_crypt to reveal the combination after the expiry time.
6. Set the combination into your lock(s).
7. Test the lock(s) out multiple times with the combination.
8. Enter in the combination one last time. Based on Miller's law, the combination will be forgotten after some time.
9. After the expiry time, retrieve the key.
10. Enter in the key into time_crypt.
11. If the current time is after the expiry time, time_crypt will output the combination based on the key. If it is before the expiry time, time_crypt will inform when it can be retrieved.
12. Enter in the combination into the lock(s) to redeem the amount of time between the lock to the expiry time.

Although the number of digits can be configured, the 8 digits that were meant to be "forgotten" is based on Miller's law that humans are able to remember about 7, plus or minus 2, objects in their short-term memory. 8 digits were also chosen because of the lack of availability of commerical locks and safes with more than 8 digits for their unlock combinations.

## Endpoints

### `test`
A test of the HTTP server.

### `create`
Generates a new passcode at the specified time by encoding the passcode and the expiry time into a new PGP message utilizing the SaaS's private key. This returns a self-expiring key that the user can save.

### `unlock`
Decrypt the key and validating if the message generated can be unlocked based on time. If it is, return the passcode.

## Quick Install

- The software runs on Python 3. We can install all libraries by running the command `pip install` and then the library, e.g. `pip install fastapi` and then `pip install "uvicorn[standard]"`, etc.  
- If configured to utilize decentralized encryption, please install Go and the [tlock dependency](https://github.com/drand/tlock).


### Python

This overviews the packages required with Python. Please reference the `requirements.txt` for the most up-to-date details.

```
fastapi
uvicorn[standard]
pgpy
python-dateutil
requests
ntplib
```

## Configuration
A configuration file can be set by defining the path of a JSON file as an environment variable called `KEYS_JSON`. If it's not set, all these parameters are assumed to be False. This can have the following parameters:

- `OFFLINE`: If true, it won't utilize the NTP servers and instead utilize the system time. Note that offline mode can be exploited by changing system time with root access.
- `TIME_CRYPT_PASS`: Manualy set the passcode for the PGP private key. Otherwise, it will be randomly generated. Note that this can be utilized as a failsafe because root access can get the PGP keys with a memory dump with relative ease.
- `DRAND`: When set to true, this informs the API to utilize drand tlock (distributed randomness time lock). The PGP message is sent to the distributed network with a calculated expiration duration. 
- `TLE_PATH`: The path of the tle (https://github.com/drand/tlock) Go binary. Required only with the `DRAND` variable and accessed to pass commands with Python's subprocess module.

Examples:

```json
{
  "OFFLINE": true
}
```
```json
{
 "DRAND": true,
 "TLE_PATH": "/home/user/go/bin/tle"
}
```

## Production Install

`KEYS_JSON=./keys.json nohup uvicorn main:app --host 0.0.0.0 --port 31415 &`

### Setting up timecrypt.service in Ubuntu

#### 1. Save the Service File
If you haven't already, save the content below to a file named `timecrypt.service`.

```
[Unit]
Description=The SaaS for time_crypt
After=network.target

[Service]
WorkingDirectory=/git/clone/path/time_crypt/
ExecStart=/which/uvicorn main:app --reload --host 0.0.0.0 --port 31415
Restart=always
Environment="KEYS_JSON=/path/to/keys.json"

[Install]
WantedBy=multi-user.target
```

#### 2. Move the Service File to systemd Directory
```
sudo cp timecrypt.service /etc/systemd/system/
```

#### 3. Ensure Uvicorn is Accessible

If you installed Uvicorn using pip, you can find its path with:

```
which uvicorn
```

If a path is returned, it's globally accessible. Otherwise, adjust your PATH variable or provide the full path in the service file.

#### 4. Reload systemd
```
sudo systemctl daemon-reload
```

#### 5. Start and Enable the Service
Start the service:
```
sudo systemctl start timecrypt.service
```
Enable the service to start on boot:
```
sudo systemctl enable timecrypt.service
```

#### 6. Check the Service Status
To ensure your service has started successfully and to view its logs, use:
```
sudo systemctl status timecrypt.service
```

### Maintaining Uptime

In highly secure configurations, if the process stops, the private key is lost. To maintain the uptime of `timecrypt`, a system service is created. There are still other factors to consider,
- Unattended upgrades by _systemd_. Consider editing the `/etc/apt/apt.conf.d/50unattended-upgrades` to include `timecrypt` in the `Unattended-Upgrade::Package-Blacklist`.

### Notes

- For a production deployment, consider removing the `--reload` flag in the `ExecStart` command. The reload flag is more suited for development as it restarts the server when code changes are detected.
- If you face any errors or the service doesn't start, follow diagnostic steps to check and debug any issues.


## User interface

From the root directory,
```
python -m http.server
```
