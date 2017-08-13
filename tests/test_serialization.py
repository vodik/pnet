from ipaddress import IPv4Address
import socket

import pnet
import pytest


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

    ipv4 = pnet.parse('ipv4', data)
    assert ipv4.readonly
    assert ipv4['src'] == IPv4Address('10.10.11.20').packed
    assert ipv4['dst'] == IPv4Address('10.200.0.5').packed
    assert ipv4['p'] == socket.IPPROTO_UDP
    assert ipv4['len'] == 139

    udp = pnet.parse('udp', ipv4.payload)
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

    ipv4 = pnet.parse('ipv4', data)
    assert not ipv4.readonly
    assert ipv4['src'] == IPv4Address('10.10.11.20').packed
    assert ipv4['dst'] == IPv4Address('10.200.0.5').packed
    assert ipv4['p'] == socket.IPPROTO_UDP
    assert ipv4['len'] == 139

    udp = pnet.parse('udp', ipv4.payload)
    assert not udp.readonly
    assert udp['sport'] == 2130
    assert udp['dport'] == 514
    assert udp['len'] == 119

    payload = udp.payload
    assert not payload.readonly
    payload == (b'<54>Jul 29 19:49:45 vega4x4 TELNET : LOG: 29/07/2017 '
                b'19:49:45.000 TELNET (C)R01C00 (user:admin)log display off\n')
