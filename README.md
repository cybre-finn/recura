# recura
Recura is a simple CLI tool for ARP Poisoning in Python. It is using the scapy library.
## Getting started
1. `git clone https://github.com/ikarulus/recura.git`
2. `cd recura`

### Requirements
* python2.7
* scapy

### Exec
`./recura.py`

## Usage
```
recura.py [-h] -i INTERFACE -v VICTIM -r ROUTER [-f]usage: recura.py [-h] -i INTERFACE -v VICTIM -r ROUTER [-f]
Careful ARP-Poisoning tool
optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Your interface
  -v VICTIM, --victim VICTIM
                        The victim's IP
  -r ROUTER, --router ROUTER
                        The gateway's IP
  -f, --forwarding      Enable forwarding to sniff packages
```

## Workflow example
1. `./recura.py -i wlan0 -v 192.168.0.10 -r 192.168.0.1 -f`
2. Sniff packages via Wireshark or tcpdump on interface wlan0
