
"""
    Script to implement the base sequence of malicious traffic to inject against a device/subnet.
    Referred to Thesis Project documents MUD_project_exp_steps_v*.

    Routine based on periods t:
    t_1     NormalOps
    t_2	    NormalOps
    t_3	    Scan
    t_4	    Scan
    t_5	    NormalOps
    t_6	    NormalOps
    t_7	    DoS
    t_8	    DoS
    t_9	    NormalOps
    t_10    NormalOps

    Where normalOps can be intended as a period without attack.
"""

"""
    Implementation:
        - consider one specific device IP as input
        - take fixed time duration for each step
        - Implement executions with timeouts
        - TODO NEW TODO PARAMETRIZE ON TASK PER PERIOD! Like, aside from the standard above defined, what if the 'events' are shifted by 1 t
            * create something like a 'sequence constructor', over a fixed number of t_'s : 'nnssnnddnn', 'nnndddnnnn', etc.
        - NOTE: hard-code each malicious attack type (i.e., do not make it parametric, just edit the code)


NOTE NOTE NOTE: TEST REAL CVS ATTACKS AGAINST DEPLOYMENT LAB DEVICES

"""

import dos
import scan

import time

MAX_EVENTS = 10
DOS_TAG = 'd'
SCAN_TAG = 's'
NOPS_TAG = 'n'

# NOTE: Consider usage of higher-order functions to generate routine-specific functions

def dos_event(target, t):
    """Performs DoS for specified amount of time"""
    dos.dos(target=target, timeout_s=t, method='synflood', spoof=True, dports=[80, 8080])

def scan_event(target, t):
    """Performs scan for specified amount of time"""
    scan.base_scan(target=target, scan_type='syn', host_detection=False, top_ports=1024, timeout=t)

def nops_event(t):
    print(f'>>> Normal operations for {t} seconds...')
    for i in range(t):
        print(f'>>> {i+1}...')
        time.sleep(1)
    print('')

def perform_routine(events, t, target):
    le = list(events)
    if len(le) > MAX_EVENTS:
        raise ValueError(f'>>> ERROR: Maximum events supported: {MAX_EVENTS} - your events string has {len(le)} events.')

    for e in le:
        if e != DOS_TAG and e != SCAN_TAG and e != NOPS_TAG:
            raise ValueError(f'>>> ERROR: Unsupported or unrecognised event {e} specified in the events chain.')

    for e in le:
        if e == DOS_TAG:
            dos_event(target, t)
        elif e == SCAN_TAG:
            scan_event(target, t)
        elif e == NOPS_TAG:
            nops_event(t)

if __name__ == '__main__':
    print('Testing experiments routines!')

    events = 'nnssnn'
    target = '192.168.1.68'
    t = 3

    perform_routine(events, t, target)

