from .packet import Packet


class Ethernet(Packet):
    __header__ = (('dst', '6s'),
                  ('src', '6s'),
                  ('type', 'H'))
