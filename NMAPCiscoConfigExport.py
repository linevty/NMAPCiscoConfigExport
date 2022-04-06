#
# pre-req's on mac os x
#
#   1. pip3 install --upgrade pip==20.2.2
#
#   2. pip install netmiko
#
#   3. pip install python-nmap
#
# to run script use ' python3 NMAPCiscoConfigExport.py 192.168.1.0/24 '
#

import nmap
import sys
import re

from netmiko import ConnectHandler
from netmiko.ssh_exception import NetMikoTimeoutException
from netmiko.ssh_exception import SSHException
from netmiko.ssh_exception import AuthenticationException

print ('\n\n^^^^^^^^^^\nPlease wait while scanning: ' +  sys.argv[1] + ' ...\n')


f = open("INPUT-nmap-devices.txt", "w+")
f.close()

nm = nmap.PortScanner()

nm.all_hosts()

nm.scan(hosts=sys.argv[1], arguments='-n -sP -PE -PA22')

hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]

for host, status in hosts_list:
    f = open("INPUT-nmap-devices.txt", "a")
    f.write(host)
    f.write("\n")
    print (host + ' added to device list')
    f.close()


with open("INPUT-nmap-devices.txt") as file:
    ip_list =file.read().splitlines() 

print ('\n\n^^^^^^^^^^\nAttempting SSH Access to each device in device list\n')

#loop all ip addresses in ip_list
for ip in ip_list:
    cisco = {
    'device_type':'cisco_ios',
    'ip':ip,
    'username':'cisco',
    'password':'cisco',
    'secret': 'cisco',
    'ssh_strict':False,  
    'fast_cli':False,
    }
    
    #handling exceptions errors
    
    try:
        net_connect = ConnectHandler(**cisco)
        print(ip + " Connected")
    except NetMikoTimeoutException:
        print(ip + " Timeout")
        continue
    except AuthenticationException:
        print(ip + " Auth Issue")
        continue
    except SSHException:
        print(ip + " SSH Issue")

        continue

    try:
        net_connect.enable()

  
    except ValueError:
        print(ip + " enable password issue")
        continue
    

    sh_ver_output = net_connect.send_command('show version')   

    regex_hostname = re.compile(r'(\S+)\suptime')

    hostname = regex_hostname.findall(sh_ver_output)

    hostnamestr = hostname[0]

    sh_cdp_output = net_connect.send_command('show cdp neighbors')   

    sh_intstatus_output = net_connect.send_command('show interface status')   

    sh_run_output = net_connect.send_command('show running-config') 

    f = open("OUTPUT-" + hostnamestr + '-' + ip + ".txt", "w+")
    f.close()

    f = open("OUTPUT-" + hostnamestr + '-' + ip + ".txt", "a")
    f.write("--------------------------------\n")
    f.write("-- SHOW VER OUTPUT\n")
    f.write("--------------------------------\n")
    f.write("\n\n")
    f.write(sh_ver_output)
    f.write("\n\n\n\n")
    f.write("--------------------------------\n")
    f.write("-- SHOW CDP OUTPUT\n")
    f.write("--------------------------------\n")
    f.write("\n\n")
    f.write(sh_cdp_output)
    f.write("\n\n\n\n")
    f.write("--------------------------------\n")
    f.write("-- SHOW INT STATUS OUTPUT\n")
    f.write("--------------------------------\n")
    f.write("\n\n")
    f.write(sh_intstatus_output)
    f.write("\n\n\n\n")
    f.write("--------------------------------\n")
    f.write("-- SHOW RUN OUTPUT\n")
    f.write("--------------------------------\n")
    f.write("\n\n")
    f.write(sh_run_output)
    f.write("\n\n\n\n")
    f.close()