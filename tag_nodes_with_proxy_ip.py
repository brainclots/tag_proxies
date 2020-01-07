'''
Script to tag all nodes with proxy IP

Author:
            ___  ____ _ ____ _  _    _  _ _    ____ ___ ___
            |__] |__/ | |__| |\ |    |_/  |    |  |  |    /
            |__] |  \ | |  | | \|    | \_ |___ |__|  |   /__

            Tripwire MSE

Version: 1.0
Date: October 2019

Assumptions:
   1. A rule exists to gather the proxy IP in use from the agent config file (storing in an element named 'proxy_ip')
   2. A Tag Set named "Proxy Host" exists.
   3. A saved filter, named "No Proxy Tagged",  is in place that contains all nodes with monitoring enabled but no
      proxy host tag.
   4. There is a TECommander auth file for the console in question, that is accessible from where the script is to be
      run (where TECommander is installed)
'''

import xmltodict
from  customer_dict import customer_dict
from pathlib import Path, PureWindowsPath
import click
import subprocess
import time
from datetime import date

tecmdr_windir = PureWindowsPath('C:/Program Files/Tripwire/tw-tecommander')
tecmdr = tecmdr_windir / 'bin' / 'tecommander.cmd'

@click.command()
@click.option('-s', '--setup', is_flag=True, help='Creates required tag set and saved filter')
@click.argument('customer')


def main(customer, setup):
    start = time.time()
    if customer in customer_dict.keys():
        cust_values = customer_dict[customer]
    else:
        print(f'ERROR: \"{customer}\" is not a valid customer! \nRun \"customer_dict.py\" to get a list of valid customers.')
        exit(1)
    if setup:
        createtagset = [f'"{str(tecmdr)}"',
                        'avcreatetag',
                        '-S "Proxy Host"',
                        '-T "Setup"',
                        f'-M {cust_values["auth_file"]}',
                        '-Q -q']
        try:
            print('Creating tagset \"Proxy Host\"...')
            subprocess.run(' '.join(createtagset), shell=True)
        except subprocess.CalledProcessError as err:
            print('Error: ', err.returncode, err.output)

        createfilter = [f'"{str(tecmdr)}"',
                        'avcreatefilter',
                        '-N "No Proxy Tagged"',
                        '-T "Status/Monitoring Enabled;Device Severity/Normal;Proxy Host/Untagged;Agent Type/Agent - Axon;Agent Type/Agent - Java"',
                        f'-M {cust_values["auth_file"]}',
                        '-Q -q']
        try:
            print('Creating saved filter \"No Proxy Tagged\"...')
            subprocess.run(' '.join(createfilter), shell=True)
        except subprocess.CalledProcessError as err:
            print('Error: ', err.returncode, err.output)

    proxy_ip_report = pull_report(customer, cust_values['auth_file'])
    with open(proxy_ip_report) as fd:
        doc = xmltodict.parse(fd.read())

    if doc['ReportOutput']['ReportBody']['Integer']['#text'] == '0':
        print('No nodes were returned with a \'proxy_ip\' element! \nPlease troubleshoot and try again.')
        return
    else:
        known_proxies = []
        to_tec = []
        for i in range(len(doc['ReportOutput']['ReportBody']['ReportSection'])):
            currentnode = doc['ReportOutput']['ReportBody']['ReportSection'][i]
            node = currentnode['String'][0]['#text']
            proxy = currentnode['ReportSection']['ReportSection']['ReportSection']['ReportSection']['String'][0]['#text']
            if not proxy in known_proxies:
                known_proxies.append(proxy)
            to_tec.append(f'avtagasset -n {node} -S "Proxy Host" -T {proxy} -M {cust_values["auth_file"]} -Q -q')
        with open(f'{customer}-tags.tec', 'w') as f:
            for proxy in known_proxies:
                f.write(f'avcreatetag -S "Proxy Host" -T {proxy} -M {cust_values["auth_file"]} -Q -q\n')
            for cmd in to_tec:
                f.write(f'{cmd}\n')
        print(f'Commands to tag nodes are in {customer}-tags.tec\nRun \'tecommander @{customer}-tags.tec\'')


def pull_report(customer, auth_file):
    cmd_list = [f'"{str(tecmdr)}"',
               'report',
    	       '-T "Which Proxy for each node"',
    	       '-t elementcontents_rpt',
    	       '-P "BooleanCriterion,currentVersionsOnly,true:MatchCriterion,elementName,equals,proxy_ip:SelectCriterion,elementExists,Yes,yes"',
    	       '-F xml',
    	       '-w "No Proxy Tagged"',
    	       f'-o "{customer}-proxy.xml"',
    	       f'-M {auth_file}',
    	       '-Q -q']

    try:
        print(f"\n    Running report of nodes with proxy_ip element on the {customer} console...\n")
        subprocess.run(' '.join(cmd_list), shell=True)
        outfile = Path(f'{customer}-proxy.xml')
    except subprocess.CalledProcessError as err:
        print('Error: ', err.returncode, err.output)

    try:
        outfile.exists()
    except NameError:
        print('\nNo output obtained from TECommander. Troubleshoot accordingly.')
        exit(1)
    #else:
        #content = output.decode('utf-8').splitlines()
    return outfile


if __name__ == '__main__':
    main()
