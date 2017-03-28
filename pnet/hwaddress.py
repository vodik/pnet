class HWAddress(object):
    """Represent and manipulate MAC addresses."""

    def __init__(self, address):
        if isinstance(address, bytes) and len(address) == 6:
            self.packed = address
        elif isinstance(address, HWAddress):
            self.packed = address.packed
        else:
            self.packed = bytes.fromhex(address.translate({45: None, 58: None}))
            if len(self.packed) != 6:
                raise ValueError("Expected 6 octets in {!r}".format(address))

    def __str__(self):
        return ':'.join(format(x, '02x') for x in self.packed)

    def __bytes__(self):
        return self.packed

    def __repr__(self):
        return "HWAddress('{}')".format(self)
