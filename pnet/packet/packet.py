import struct


def configure_packet_header(hdrs, header_fmt):
    for attr, fmt in hdrs:
        header_fmt.append(fmt)
        yield attr


class MetaPacket(type):
    def __new__(mcs, clsname, clsbases, clsdict):
        headers = clsdict.get('__header__', [])
        header_format_order = clsdict.get('__byte_order__', '>')
        header_format = [header_format_order]

        slots = tuple(configure_packet_header(headers, header_format))
        header_struct = struct.Struct(''.join(header_format))

        clsdict['__slots__'] = ('_fields', '_view', '_payload')
        clsdict['_header_fields'] = slots
        clsdict['_header_bytes_order'] = header_format_order
        clsdict['_header_struct'] = header_struct
        clsdict['_header_size'] = header_struct.size

        return type.__new__(mcs, clsname, clsbases, clsdict)

    def __len__(self):
        return self._header_size


class Packet(metaclass=MetaPacket):
    def __init__(self, view=None):
        if not view:
            self._view = memoryview(bytearray(self._header_size))
            return

        self._view = memoryview(view)
        self._payload = self._view[self._header_size:]

        values = self._header_struct.unpack_from(self._view[:self._header_size])
        self._fields = dict(zip(self._header_fields, values))

    def __getitem__(self, key):
        return self._fields[key]

    def __setitem__(self, key, value):
        if self._view.readonly:
            raise TypeError("'{}' is backed by a readonly "
                            "view".format(self.__class__.__name__))

        # Repack structure whenever key is updated
        self._fields[key] = value
        values = tuple(self._fields[key] for key in self._header_fields)
        self._header_struct.pack_into(self._view, 0, *values)

    def __len__(self):
        return len(self._view)

    def __bytes__(self):
        return bytes(self._view[:self._header_size])

    @property
    def view(self):
        return self._view[:self._header_size]

    @property
    def payload(self):
        return self._payload

    @property
    def readonly(self):
        return self._view.readonly


class IP(Packet):
    __header__ = (("v_hl", "B"),
                  ("tos", "B"),
                  ("len", "H"),
                  ("id", "H"),
                  ("frag_off", "H"),
                  ("ttl", "B"),
                  ("p", "B"),
                  ("sum", "H"),
                  ("src", "4s"),
                  ("dst", "4s"))


class UDP(Packet):
    __header__ = (('sport', 'H'),
                  ('dport', 'H'),
                  ('len', 'H'),
                  ('csum', 'H'))
