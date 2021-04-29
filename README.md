# PV204-NoisyTPM
Project for FI:PV204

## Assignment
Secure Channel with Noise Protocol and TPM
- Establish forward-secure channel between client and server over TCP/IP with Noise protocol
- Initial registration
  - Client registers to server, authentication is not required
  - Pre-shared value can be set
- Subsequent communication
  - Server and client need to be authenticated
  - Changes to client should be detected (TPM)
    - User should be informed
    - Secure channel should not be established
- Implement some auxiliary functionality
  - E.g., simple message board
  
### Resources
- [Noise Protocol Framework](http://www.noiseprotocol.org/)
- [TPM2 Tools](https://github.com/tpm2-software/tpm2-tools)
- [TSS.MSR](https://github.com/microsoft/TSS.MSR)
___

#### TPM Simulator prerequisite
When connecting to a TCP TPM, a simulator needs to be running and listening on port 2321.

On Windows, you can use a pre-compiled [TPM 2.0 simulator](https://www.microsoft.com/en-us/download/details.aspx?id=52507) provided by Microsoft.

On Linux, you have to [download](https://sourceforge.net/projects/ibmswtpm2/) and build IBM TPM server. Then add the binary `tpm_server` to the `$PATH`.

#### Prerequisities
To run server, you will need to do following steps:

1. set up venv environment (run in project directory)

Windows:
`python -m venv venv`

Linux: `python3 -m venv venv`

2. start virtual environment

Windows: `./venv/Scripts/activate`

Linux: `source venv/bin/activate`

3. install requirements
`pip install -r requirements.txt`

### Usage

#### Server
You will first need to start the server. If you have all necessary prerequisites, simply run 

```Python
python3 server.py
```

Note that you may want to change default settings like ports or log level in `constants.py`.
On the console, you will receive logs from Flask frontend and from our communicator, which can help understand the process.

Server is supposed to be run in "safe" environment, meaning that itself it does not protect any data stored locally.

#### Client
Client is standalone application which connect to local TPM (or simulator - change settings in `constants.py`) and then estabilish secure connection to the server.
Before you can send messages, you will need to register (provide your keys and PCR hash) to the server.

```Python
python3 client.py -s <server> -p <noise port> -r
```

After registration, you can start writing messages, which can be seen on the server's frontend.

You can also quit application, it will store the user info and next time it can be run without registration.

```Python
python3 client.py -s <server> -p <noise port>
```

For more info, please use `python3 client.py -h`.

### Additional information

#### Demo - change of TPM value

To simulate change in TPM PCR values, we can use simulator. (You will also need to change the corresponding variable in `constants.py`)

Then register to the server using `python3 client.py -r`.

Lastly, run `python3 client_demo_compromised.py`, which is a variant of `client.py` that changes PCR value. You shall receive an error message and the connection would not be estabilished.

#### Code formatting
If you want to apply code formatter `black` on `.py` files, install black:
```
pip install black
```
then to format `.py` files run:
````
black *.py --line-length 120
````

#### API calls

In order to register new client, one may send a POST request to `<URL>:5000/register` with the following body:
```JSON
{
    "username": "User Name",
    "pubkey": "Public Key from TPM",
    "pcr_hash": "Hash of PCR values from TPM"
}
```

To purge the entries (util function for demonstration purposes only) one can send POST request to `<URL>:5000/purge` with following body:
```JOSN
{
  "magic":"please"
}
```
WARNING: All messages and users will be deleted even from serialized data!
   
#### Note on usage of physical TPM on Linux
It is possible that using physical TPM on Linux will require you to set your access permissions accordingly.
More on this issue [here](https://superuser.com/questions/1463364/accessing-trusted-platform-moduletpm-without-root-permission).
