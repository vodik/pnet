import struct
from .. import entrypoints


class MetaPacket(type):
    def __new__(mcs, clsname, clsbases, clsdict):
        headers = clsdict.get('__header__', [])
        if headers:
            header_attrs, header_fmt = zip(*headers)
            header_format_order = clsdict.get('__byte_order__', '>')
            header_format = [header_format_order] + list(header_fmt)
            header_struct = struct.Struct(''.join(header_format))

            clsdict['__slots__'] = ('_fields', '_view', '_payload')
            clsdict['_header_fields'] = tuple(header_attrs)
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

    def parse(self, name):
        return entrypoints.get_parsers()[name](self.payload)
