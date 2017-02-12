import os


def get_input(argv):
    if len(argv) < 2:
        print 'please specify target directory'
        return
    network_dir = argv[1]
    if not os.path.isdir(network_dir):
        print 'please specify valid directory'
        return
    if len(argv) > 2:
        max_num = int(argv[2])
        print 'max num: ', max_num
    else:
        print 'no max num specified'
        max_num = None
    return network_dir, max_num
