#!/usr/local/bin/python3

from config import icinga_user
from config import icinga_pass
from config import icinga_host
from config import icinga_time_period
from config import icinga_changes_crit
from config import icinga_changes_warn

import sys
import requests
import json
import datetime
from os import path

# pip3 install urllib3[secure]
import urllib3
# See below verify=False when using self-signed cert internally
urllib3.disable_warnings()

# settings for script
f_log = open('adjchange.log', 'a')

# EXEC ./AdjStateChange.py $r $1 $2 $3 $4
# hostname ($r)
hostname = sys.argv[1]
# ciiNotifIsLevelIndex ($1)
level = sys.argv[2]
# ciiCircIfIndex ($2)
if_index = sys.argv[3]
# ciiPduLspId ($3)
lsp_id = sys.argv[4]
# ciiAdjState ($4)
adj_state = sys.argv[5]

plugin_output = 'ciiNotifIsLevelIndex=' + level + ', ciiCircIfIndex=' + if_index + ', ciiPduLspId=' + lsp_id + ', ciiAdjState=' + adj_state
f_log.write(datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f%z') + ' ' + hostname + ' data from snmp: ' + plugin_output + '\n')

#  'filter': 'host.name=="dist02.tor1" && service.name=="Adjacency-Change"', 
icinga_filter = 'host.name=="' + hostname + '" && service.name=="Adjacency-Change"'

hostname_logfile = './hosts/' + hostname + '.log'

data =  { 
 'type': 'Service',
 'plugin_output': plugin_output,
 'filter': icinga_filter
}

def IcingaStatus(lines, time_peroid, time_str_now, changes):
    if(len(lines) < changes):
        return False
    else:
        lines_last = lines[-1*changes:]

    line_items = lines_last[0].split()

    time_obj_now = datetime.datetime.strptime(time_str_now, '%Y-%m-%dT%H:%M:%S.%f')
    time_obj_line = datetime.datetime.strptime(line_items[1], '%Y-%m-%dT%H:%M:%S.%f')
    time_obj_delta = time_obj_now - time_obj_line

    time_delta_in_s = round(time_obj_delta.total_seconds())

    if(time_delta_in_s <= time_peroid):
        return True
    else:
        return False


# adjState
#  1: down
#  2: initializing
#  3: up
#  4: failed
adj_state_valid = ['1', '2', '4']

# icinga
# For services: 0=OK, 1=WARNING, 2=CRITICAL, 3=UNKNOWN
update_icinga = True

if(adj_state == '3'):
    data['exit_status'] = 0

else: 
    date_str_now = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f%z')

    # avoid a new line at the start of new file
    if(path.exists(hostname_logfile)):
        line_new = '\n' + adj_state + ' ' + date_str_now
    else:
        line_new = adj_state + ' ' + date_str_now

    with open(hostname_logfile, 'a') as f:
        f.write(line_new)
  
    with open(hostname_logfile, 'r') as f:
        lines = f.readlines()
    
    if(adj_state in adj_state_valid):
        if(IcingaStatus(lines, icinga_time_period, date_str_now, icinga_changes_crit)):
            data['exit_status'] = 2

        elif(IcingaStatus(lines, icinga_time_period, date_str_now, icinga_changes_warn)): 
            data['exit_status'] = 1
        
        else:
            update_icinga = False

    else: 
        data['exit_status'] = 3


if(update_icinga):
    f_log.write(datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f%z') + ' ' + hostname + ' exit_status: ' + str(data['exit_status']) + '\n')

    headers = {
        'Accept': 'application/json',
    }

    response = requests.post(icinga_host, headers=headers, data=json.dumps(data), verify=False, auth=(icinga_user, icinga_pass))
    f_log.write(datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f%z') + ' ' + hostname + ' icinga response: ' + str(response.status_code) + '\n')

else: 
    f_log.write(datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f%z') + ' ' + hostname + ' POST request not sent to icinga api\n')


# EVENT ciiAdjacencyChange .1.3.6.1.4.1.9.10.118.0.17 "Status Events" Normal
# FORMAT ISIS adj chg: Level $1, ifIndex $2, lspId $3, AdjState $4
# # EXEC /usr/local/bin/snmptt-send-mail 3 usre@domain.tld "ISIS $r alert: ISIS-adj" "ISIS: adj chg: Level $1, ifIndex $2, lspId $3, AdjState $4"
# # PATH TO PYTHON3
# EXEC /usr/local/bin/python3 adjchange.py $r $1 $2 $3 $4
# SDESC
# A notification sent when an adjacency changes
# state, entering or leaving state up.
# The first 6 bytes of the ciiPduLspId are the
# SystemID of the adjacent IS.
# The ciiAdjState is the new state of the adjacency.
# Variables:
#   1: ciiNotifIsLevelIndex
#      Syntax="INTEGER"
#        1: level1IS
#        2: level2IS
#      Descr="The index value used in this notification
#               to indicate the system level."
#   2: ciiCircIfIndex
#      Syntax="INTEGER32"
#      Descr="The value of ifIndex for the interface to which this
#              circuit corresponds.   This object cannot be modified
#              after creation"
#   3: ciiPduLspId
#      Syntax="OCTETSTR"
#      Descr="An Octet String that uniquely identifies
#              a Link State PDU."
#   4: ciiAdjState
#      Syntax="INTEGER"
#        1: down
#        2: initializing
#        3: up
#        4: failed
#      Descr="The current state of an adjacency."
# EDESC