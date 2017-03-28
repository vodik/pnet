from .packet import Packet


class Cooked(Packet):
    __header__ = (('pkttype', 'H'),
                  ('hatype', 'H'),
                  ('halen', 'H'),
                  ('src', '6s'),
                  ('pad', 'H'),
                  ('type', 'H'))
