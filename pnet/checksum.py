import struct
from .packet.udp import UDP


def checksum(*data):
    data = b''.join(data)
    if len(data) % 2:
        data += b'\x00'

    csum = sum(struct.unpack('!H', data[x:x+2])[0]
               for x in range(0, len(data), 2))

    csum = (csum >> 16) + (csum & 0xffff)
    csum += csum >> 16
    return ~csum & 0xffff


def ipv4_checksum(ip4, udp, payload):
    ip4_src = ip4['src']
    ip4_dst = ip4['dst']
    ip4_len = len(payload) + len(UDP)
    return checksum(ip4_src or b'\x00' * 4,
                    ip4_dst or b'\x00' * 4,
                    struct.pack('!HH', ip4['p'], ip4_len),
                    udp.view,
                    payload)
