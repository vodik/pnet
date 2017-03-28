from .packet import Packet


class UDP(Packet):
    __header__ = (('sport', 'H'),
                  ('dport', 'H'),
                  ('len', 'H'),
                  ('csum', 'H'))
