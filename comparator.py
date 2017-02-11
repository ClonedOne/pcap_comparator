from domain.reduced_pcap import ReducedPcap
from pprint import pprint
import scapy.all as scapy
import time
import sys
import os


def pcap_to_pckt_freqs(pcap, red_pcap):
    for packet in pcap:
        sum = packet.summary()
        red_pcap.packet_freqs[sum] = red_pcap.packet_freqs.get(sum, 0) + 1


def get_reduced_pcaps(dir_files, size):
    red_p_list = []
    i = 0.0
    for net_log in dir_files:
        i += 1
        pcap = scapy.rdpcap(net_log)
        red_pcap = ReducedPcap(pcap)
        pcap_to_pckt_freqs(pcap, red_pcap)
        red_p_list.append(red_pcap)
        print "Reading files: {:.2f}".format(i/size)
    return red_p_list


def find_constant_packets(red_p_list, size):
    temp_key_list = []
    i = 0.0
    for red_p in red_p_list:
        i += 1
        temp_key_list.append(set(red_p.packet_freqs.keys()))
        print "Finding Constants: {:.2f}".format(i / size)
    return set.intersection(*temp_key_list)


def find_different_packets(const_pckt_keys, red_p_list, size):
    i = 0.0
    for red_p in red_p_list:
        i += 1
        cur_keys = set(red_p.packet_freqs.keys())
        diff = cur_keys.difference(const_pckt_keys)
        red_p.diff_pckts = diff
        print "Finding Differences: {:.2f}".format(i / size)


def get_file_list(network_dir, max_num):
    dir_files = sorted(os.listdir(network_dir))
    if len(dir_files) == 0 or max_num == 0:
        print 'No pcap files to work on'
        exit()
    res_files = []
    counter = 0
    for cur_file in dir_files:
        if counter == max_num:
            break
        if cur_file[-5:] != '.pcap':
            continue
        res_files.append(os.path.join(network_dir, cur_file))
        counter += 1
    return res_files, len(res_files)


def output_on_file(red_p_list, const_pckts):
    with open('pcap_diff.txt', 'w') as out_file:
        out_file.write(
            '{:36}\t{:10}\t{:10}\t{:10}\t{:10}\t{:10}\n'.format(
                'Log file',
                'Different',
                'Num TCP',
                'Num UDP',
                'Num ICMP',
                'Num Other'
            )
        )
        for red_p in red_p_list:
            out_file.write(
                '{:36}\t{:10}\t{:10}\t{:10}\t{:10}\t{:10}\n'.format(
                    red_p.name,
                    str(len(red_p.diff_pckts)),
                    str(red_p.num_tcp),
                    str(red_p.num_udp),
                    str(red_p.num_icmp),
                    str(red_p.num_other)
                )
            )
        out_file.write('\nConstant Summaries')
        pprint(const_pckts, out_file)


def main():
    if len(sys.argv) < 2:
        print 'please specify target directory'
        return
    network_dir = sys.argv[1]
    if not os.path.isdir(network_dir):
        print 'please specify valid directory'
        return
    if len(sys.argv) > 2:
        max_num = int(sys.argv[2])
        print 'max num: ', max_num
    else:
        print 'no max num specified'
        max_num = None

    time_start = time.time()
    dir_files, size = get_file_list(network_dir, max_num)
    print 'number of pcap files: ', len(dir_files)
    red_p_list = get_reduced_pcaps(dir_files, size)
    const_pckts = find_constant_packets(red_p_list, size)
    find_different_packets(const_pckts, red_p_list, size)
    output_on_file(red_p_list, const_pckts)
    time_end = time.time()
    print 'Time passed:', time_end - time_start

if __name__ == '__main__':
    main()
