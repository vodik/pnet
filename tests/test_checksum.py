import pnet
from pnet.packet.ipv4 import IPv4
from pnet.packet.udp import UDP
import pytest


def test_checksum_udp_in_ipv4():
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
    udp = UDP(ip4.payload)

    original_csum = udp['csum']
    assert pnet.ipv4_checksum(ip4, udp, udp.payload) == 0

    udp['csum'] = 0
    csum = pnet.ipv4_checksum(ip4, udp, udp.payload)
    assert csum == original_csum
