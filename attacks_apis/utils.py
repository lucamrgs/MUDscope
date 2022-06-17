
import os
import ipaddress

##################################################################################################
# SOME CONSTANTS
##################################################################################################
PORTS_RANGES_REGEX = '[0-9]+(?:-[0-9]+)?(,[0-9]+(?:-[0-9]+)?)*'
MAX_PORTS = 65389
MAX_TIMEOUT_S = 600
MIN_DOS_PPS = 100
MAX_DOS_PPS = 3000


##################################################################################################
# SUPPORT FUNCTIONS
##################################################################################################

def is_valid_path(path, check_dir=True, check_file=True):
    if check_dir and check_file:
        return os.path.isfile(path) or os.path.isdir(path)
    if check_dir and not check_file:
        return os.path.isdir(path)
    if check_file and not check_dir:
        return os.path.isfile(path)
    return False

def assign_non_req(argument, default):
    return argument if argument is not None else default

def check_valid_target(target):
    # Target
    valid_tgt = False
    error = ''
    try:
        valid = ipaddress.ip_address(target)
        valid_tgt = True
    except Exception as e:
        valid_tgt = False
        error = e
    try:
        valid = ipaddress.ip_network(target)
        valid_tgt = True
    except Exception as e:
        valid_tgt = False
        error = e
    
    if not valid_tgt:
        print(error)
        raise ValueError(f'>>> ERROR: Invalid target provided [ {target} ]. Exiting.')

def check_boolean_var(var):
    if not isinstance(var, bool):
        raise ValueError(f'>>> ERROR: Parameter {var} is supposed to be boolean. Exiting.')

def check_int_var(var, min, max):
    try:
        if var is not None:
            if not (isinstance(int(var), int) and int(var) >= min and int(var) <= max):
                raise ValueError(f'>>> ERROR: Parameter {var} is supposed to be an integer in [{min}, {max}]. Exiting.')
    except Exception as e:
        print(e)
        raise ValueError(f'>>> ERROR: Parameter {var} is supposed to be an integer in [{min}, {max}]. Exiting.')

def check_string_value(var, values):
    if not (isinstance(var, str) and var in values):
        raise ValueError(f'>>> ERROR: Parameter {var} is supposed to be a string of value (one of) {values}. Exiting.')

if __name__ == '__main__':
    print('Testing!')