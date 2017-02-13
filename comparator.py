from domain.pcap_parser import get_reduced_pcaps
from utils import general_utils
from utils import file_utils
import time
import sys


def find_constant_packets(red_p_list, size):
    temp_key_list = []
    i = 0.0
    for red_p in red_p_list:
        i += 1
        temp_key_list.append(set(red_p.packet_freqs.keys()))
        print("Finding Constants: {:.2f}".format(i / size))
    return set.intersection(*temp_key_list)


def find_different_packets(const_pckt_keys, red_p_list, size):
    i = 0.0
    for red_p in red_p_list:
        i += 1
        cur_keys = set(red_p.packet_freqs.keys())
        diff = cur_keys.difference(const_pckt_keys)
        red_p.diff_pckts = diff
        print("Finding Differences: {:.2f}".format(i / size))


def main():
    network_dir, max_num, to_process = general_utils.get_input(sys.argv)
    time_start = time.time()
    dir_files, size = file_utils.get_file_list(network_dir, max_num, to_process)
    print('number of pcap files: ', len(dir_files))
    red_p_list = get_reduced_pcaps(dir_files, size)
    const_pckts = find_constant_packets(red_p_list, size)
    find_different_packets(const_pckts, red_p_list, size)
    file_utils.output_on_file(red_p_list, const_pckts)
    time_end = time.time()
    print('Time passed:', time_end - time_start)


if __name__ == '__main__':
    main()
