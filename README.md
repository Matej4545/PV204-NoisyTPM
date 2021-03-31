# PV204-NoisyTPM
Project for FI:PV204

## Assignment
Secure Channel with Noise Protocol and TPM
- Establish forward-secure channel between client and server over TCP/IP with Noise protocol
- Initial registration–Client registers to server, authentication is not required
- Presharedvalue can be set
- Subsequent communication–Server and client need to be authenticated–Changes to client should be detected (TPM)
  - User should be informed
  - Secure channel should not be established
- Implement some auxiliary functionality
  - E.g., simple message board
### Resources
- Noise Protocol Framework–http://www.noiseprotocol.org/
- TPM2 Tools–https://github.com/tpm2-software/tpm2-tools

___

#### Code formatting
If you want to apply code formatter `black` on `.py` files, install black:

    pip install black
then to format `.py` files run:

    black *.py --line-length 120