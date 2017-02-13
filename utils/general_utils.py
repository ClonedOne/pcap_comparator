from utils.file_utils import get_set_to_process
import os


def get_input(argv):
    max_num = None
    to_process = None
    if len(argv) < 2:
        print('please specify target directory')
        return
    network_dir = argv[1]
    if not os.path.isdir(network_dir):
        print('please specify valid directory')
        return
    if len(argv) == 3:
        if is_int(argv[2]):
            max_num = int(argv[2])
        elif os.path.isfile(argv[2]):
            to_process = get_set_to_process(argv[2])
        else:
            print('Use: comparator.py path_to_folder [max_num, file_list]')
            exit()
    else:
        print('Use: comparator.py path_to_folder [max_num, file_list]')
        max_num = None
    return network_dir, max_num, to_process


def is_int(s):
    try:
        int(s)
        return True
    except ValueError:
        return False