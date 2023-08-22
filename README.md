# time_crypt
A cryptographic function that enables decryption based on length of time or other specified time.

## Link

https://port-1337-time_crypt-hamu515426.preview.codeanywhere.com/

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
The software runs on Python 3. We can install all libraries by running the command `pip install` and then the library, e.g. `pip install fastapi` and then `pip install "uvicorn[standard]"`, etc.  

```requirements
fastapi
"uvicorn[standard]"
pgpy
python-dateutil --upgrade
requests
```
<h2>Setting up timecrypt.service in Ubuntu</h2>

<h3>1. Save the Service File</h3>
<p>If you haven't already, save the content below to a file named <code>timecrypt.service</code>.</p>

<pre>
[Unit]
Description=The SaaS for time_crypt
After=network.target

[Service]
WorkingDirectory=/git/clone/path/time_crypt/
ExecStart=/which/uvicorn main:app --reload --host 0.0.0.0 --port 1337
Restart=always

[Install]
WantedBy=multi-user.target
</pre>

<h3>2. Move the Service File to systemd Directory</h3>
<pre>
sudo cp timecrypt.service /etc/systemd/system/
</pre>

<h3>3. Ensure Uvicorn is Accessible</h3>
<p>If you installed Uvicorn using pip, you can find its path with:</p>
<pre>
which uvicorn
</pre>
<p>If a path is returned, it's globally accessible. Otherwise, adjust your PATH variable or provide the full path in the service file.</p>

<h3>4. Reload systemd</h3>
<pre>
sudo systemctl daemon-reload
</pre>

<h3>5. Start and Enable the Service</h3>
<p>Start the service:</p>
<pre>
sudo systemctl start timecrypt.service
</pre>
<p>Enable the service to start on boot:</p>
<pre>
sudo systemctl enable timecrypt.service
</pre>

<h3>6. Check the Service Status</h3>
<p>To ensure your service has started successfully and to view its logs, use:</p>
<pre>
sudo systemctl status timecrypt.service
</pre>

<h3>Notes:</h3>
<ul>
<li>For a production deployment, consider removing the <code>--reload</code> flag in the <code>ExecStart</code> command. The reload flag is more suited for development as it restarts the server when code changes are detected.</li>
<li>If you face any errors or the service doesn't start, follow diagnostic steps to check and debug any issues.</li>
</ul>


## Quickstart

This overviews how we can utilize the API in the real-world use case that the algorithm was made for. The requirements are that this algorithm works regardless of the padlock technologies. Often, manufacturers of time-lock mechanisms make low-quality physical locks. Even if they improved, it may not be as effective against lock-picking compared to heavy-duty padlocks. Here, we present a solution that combines the two. We give the user a combination to put into multiple combination padlocks that is meant to be forgotten. If the user remembers, they can request a new random combination. The combination is made up of 8 characters or digits. This means that this algorithm can be reused for many types of combination padlock technology in the past or present without additional costs.

1. Generate a new code and input lock time. 
  - Save the cryptographic message. The SaaS will save a .txt file with the message from your web browser.
  - The application will have a setting to enable saving the passcode to your exposed IP address, it is off by default.
2. Enter the code into your padlock(s) and lock the safe.
3. Check the status of the lock and unlock time. All time unlocked codes will automatically be exposed.
  - To decrypt from an anonymous source, the SaaS can reads the message saved in step 1 in the `unlock` api and return the passcode if it's past the lock time.

Although the number of digits can be configured, the 8 digits that were meant to be "forgotten" is based on Miller's law that humans are able to remember about 7, plus or minus 2, objects in their short-term memory. 8 digits were also chosen because of the lack of availability of commerical locks and safes with more than 8 digits for their unlock combinations. 
