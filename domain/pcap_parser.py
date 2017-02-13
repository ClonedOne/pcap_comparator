from domain.reduced_pcap import ReducedPcap
from scapy.layers.inet import TCP, UDP
from scapy.all import PcapReader
import traceback


def get_reduced_pcaps(dir_files, size):
    red_p_list = []
    i = 0.0
    for net_log in dir_files:
        i += 1
        name = (net_log.split('/')[-1][:-5])
        red_p = ReducedPcap(name)
        counter_tcp = 0
        counter_udp = 0
        counter_arp = 0
        with PcapReader(net_log) as pcap_reader:
            for pkt in pcap_reader:
                summ = pkt.summary()
                try:
                    if TCP in pkt:
                        counter_tcp += 1
                    elif UDP in pkt:
                        counter_udp += 1
                    red_p.add_freq(summ)
                except Exception:
                    traceback.print_exc()
                    print(summ)
        red_p.num_tcp = counter_tcp
        red_p.num_udp = counter_udp
        red_p.num_arp = counter_arp
        red_p_list.append(red_p)
        print("Reading files: {:.2f}".format(i / size))

    return red_p_list
