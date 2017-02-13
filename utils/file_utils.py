import os


def get_set_to_process(file_path):
    pcap_files = set()
    with open(file_path, 'r') as in_file:
        for line in in_file:
            name = line.split()[0].strip()
            pcap_files.add(name)
    return pcap_files


def get_file_list(network_dir, max_num, to_process):
    dir_files = sorted(os.listdir(network_dir))
    if to_process is None:
        to_process = [log_file[:-5] for log_file in dir_files]

    if len(dir_files) == 0 or max_num == 0:
        print('No pcap files to work on')
        exit()
    res_files = []
    counter = 0
    for cur_file in dir_files:
        if counter == max_num:
            break
        if cur_file[-5:] != '.pcap':
            continue
        if cur_file[:-5] in to_process:
            res_files.append(os.path.join(network_dir, cur_file))
            counter += 1
    return res_files, len(res_files)


def output_on_file(red_p_list, const_pckts):
    with open('pcap_diff.txt', 'w') as out_file:
        out_file.write(
            '{:36}\t{:10}\t{:10}\t{:10}\n'.format(
                'Log file',
                'Different',
                'Num TCP',
                'Num UDP'
            )
        )
        for red_p in red_p_list:
            out_file.write(
                '{:36}\t{:10}\t{:10}\t{:10}\n'.format(
                    red_p.name,
                    str(len(red_p.diff_pckts)),
                    str(red_p.num_tcp),
                    str(red_p.num_udp)
                )
            )
        out_file.write('\nConstant Summaries\n')
        for key in sorted(const_pckts):
            print(key, file=out_file)