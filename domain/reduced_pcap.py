class ReducedPcap:

    def __init__(self, name):
        self.name = name
        self.num_tcp = 0
        self.num_udp = 0
        self.num_arp = 0
        self.num_icmp = 0
        self.num_other = 0
        self.packet_freqs = {}
        self.diff_pckts = set()

    def set_tcp(self, tcp):
        self.num_tcp = tcp

    def set_udp(self, udp):
        self.num_udp = udp

    def set_arp(self, arp):
        self.num_arp = arp

    def set_icmp(self, icmp):
        self.num_icmp = icmp

    def set_other(self, other):
        self.num_other = other

    def add_freq(self, summ):
        if summ in self.packet_freqs:
            self.packet_freqs[summ] += 1
        else:
            self.packet_freqs[summ] = 1
