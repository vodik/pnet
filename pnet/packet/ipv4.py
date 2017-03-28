from .packet import Packet


class IPv4(Packet):
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
