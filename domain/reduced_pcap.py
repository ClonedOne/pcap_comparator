class ReducedPcap:

    def __init__(self, pcap):
        recap = pcap.__repr__().split()
        self.name = recap[0][1:-6].strip()
        self.num_tcp = int(recap[1].split(':')[1].strip())
        self.num_udp = int(recap[2].split(':')[1].strip())
        self.num_icmp = int(recap[3].split(':')[1].strip())
        self.num_other = int(recap[4].split(':')[1][:-1].strip())
        self.packet_freqs = {}
        self.diff_pckts = set()
