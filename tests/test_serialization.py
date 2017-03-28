from ipaddress import IPv4Address
import socket

from pnet.packet.ipv4 import IPv4
from pnet.packet.udp import UDP
import pytest


# Set protocol field to a value not yet assigned by IANA.
# Set total length field to zero.
# Set total length field to maximum size.
# Set IHL and total length fields so that header goes past end of datagram.
# Destination address is set to the loopback '127.0.0.1' address.
# Destination address is set to '0.0.0.0' broadcast address.
# Destination address is set to '255.255.255.255' broadcast address.
# Source address is set to the '0.0.0.0' broadcast address.
# Source address is set to the loopback '127.0.0.1' address.
# Protocol field is 200 (unassigned) and source address is a broadcast address.
# Protocol field is 200 (unassigned) and source address is a loopback address.
# TTL field is zero and source address is a broadcast address.
# Datagram is truncated so protocol field indicates another protocol follows, but none does.
# IPv4 version field set to value other than 4.
# Adjust header so checksum is -0 and set checksum field to -0.
# Adjust header so checksum is -0 and set checksum field to +0.
# Adjust header so checksum is +1 and set checksum field to +0.
# Verify processing of TTL field.
# Change ICMPv4 destination address to '224.0.0.1' multicast address.
# Check for continuous dead gateway detection pinging.
# Check for dead gateway detection pinging while traffic being sent.
# Verify link layer broadcasts with specific addresses are discarded.
# Verify that ICMPv4 host and net redirects are treated the same.


def test_parse_packet_from_bytes():
    data = bytes.fromhex(
        '4500 008b 0000 4000 3e11 1c78 0a0a 0b14'
        '0ac8 0005 0852 0202 0077 a96b 3c35 343e'
        '4a75 6c20 3239 2031 393a 3439 3a34 3520'
        '7665 6761 3478 3420 5445 4c4e 4554 203a'
        '204c 4f47 3a20 3239 2f30 372f 3230 3137'
        '2031 393a 3439 3a34 352e 3030 3020 5445'
        '4c4e 4554 2028 4329 5230 3143 3030 2028'
        '7573 6572 3a61 646d 696e 296c 6f67 2064'
        '6973 706c 6179 206f 6666 0a'
    )

    ip4 = IPv4(data)
    assert ip4.readonly
    assert ip4['src'] == IPv4Address('10.10.11.20').packed
    assert ip4['dst'] == IPv4Address('10.200.0.5').packed
    assert ip4['p'] == socket.IPPROTO_UDP
    assert ip4['len'] == 139

    udp = UDP(ip4.payload)
    assert udp.readonly
    assert udp['sport'] == 2130
    assert udp['dport'] == 514
    assert udp['len'] == 119

    payload = udp.payload
    assert payload.readonly
    payload == (b'<54>Jul 29 19:49:45 vega4x4 TELNET : LOG: 29/07/2017 '
                b'19:49:45.000 TELNET (C)R01C00 (user:admin)log display off\n')


def test_parse_packet_from_bytearray():
    data = bytearray.fromhex(
        '4500 008b 0000 4000 3e11 1c78 0a0a 0b14'
        '0ac8 0005 0852 0202 0077 a96b 3c35 343e'
        '4a75 6c20 3239 2031 393a 3439 3a34 3520'
        '7665 6761 3478 3420 5445 4c4e 4554 203a'
        '204c 4f47 3a20 3239 2f30 372f 3230 3137'
        '2031 393a 3439 3a34 352e 3030 3020 5445'
        '4c4e 4554 2028 4329 5230 3143 3030 2028'
        '7573 6572 3a61 646d 696e 296c 6f67 2064'
        '6973 706c 6179 206f 6666 0a'
    )

    ip4 = IPv4(data)
    assert not ip4.readonly
    assert ip4['src'] == IPv4Address('10.10.11.20').packed
    assert ip4['dst'] == IPv4Address('10.200.0.5').packed
    assert ip4['p'] == socket.IPPROTO_UDP
    assert ip4['len'] == 139

    udp = UDP(ip4.payload)
    assert not udp.readonly
    assert udp['sport'] == 2130
    assert udp['dport'] == 514
    assert udp['len'] == 119

    payload = udp.payload
    assert not payload.readonly
    payload == (b'<54>Jul 29 19:49:45 vega4x4 TELNET : LOG: 29/07/2017 '
                b'19:49:45.000 TELNET (C)R01C00 (user:admin)log display off\n')
