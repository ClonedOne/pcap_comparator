from domain.reduced_pcap import ReducedPcap
from pprint import pprint
from copy import deepcopy
import scapy.all as scapy
import sys
import os


def pcap_to_pckt_freqs(pcap, red_pcap):
    for packet in pcap:
        sum = packet.summary()
        red_pcap.packet_freqs[sum] = red_pcap.packet_freqs.get(sum, 0) + 1


def get_reduced_pcaps(dir_files):
    red_p_list = []
    for net_log in dir_files:
        pcap = scapy.rdpcap(net_log)
        red_pcap = ReducedPcap(pcap)
        pcap_to_pckt_freqs(pcap, red_pcap)
        red_p_list.append(red_pcap)
    return red_p_list


def find_constant_packets(red_p_list):
    res_freqs = deepcopy(red_p_list[0].packet_freqs)
    ref_keys = red_p_list[0].packet_freqs.keys()
    for red_p in red_p_list:
        cur_freqs = red_p.packet_freqs
        for key in ref_keys:
            if key not in cur_freqs and key in res_freqs:
                res_freqs.pop(key)
            elif key in res_freqs:
                freq_res = res_freqs[key]
                freq_cur = cur_freqs[key]
                res_freqs[key] = min(freq_res, freq_cur)
    return res_freqs


def find_different_packets(const_pckt_keys, red_p_list):
    for red_p in red_p_list:
        cur_keys = set(red_p.packet_freqs.keys())
        diff = cur_keys.difference(const_pckt_keys)
        red_p.diff_pckts = diff


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
    return res_files


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
        max_num = 0

    dir_files = get_file_list(network_dir, max_num)
    print 'number of pcap files: ', len(dir_files)
    red_p_list = get_reduced_pcaps(dir_files)
    const_pckts = find_constant_packets(red_p_list)
    print 'Constant keys with minimum values: '
    pprint(const_pckts)
    const_pckt_keys = sorted(set(const_pckts.keys()))
    find_different_packets(const_pckt_keys, red_p_list)
    for red_p in red_p_list:
        print red_p.name, len(red_p.diff_pckts)


if __name__ == '__main__':
    main()
