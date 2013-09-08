#!/usr/bin/env python2.7
import os
import subprocess
import sys
import json
import re
import ast
#
# A simple python utility which helps monitoring and debugging 
# the flows set at the switch (using OF1.3). It displays the flows per 
# table in a more convinient way. 
# It uses the dpctl tool to send the flow stats req.
# 
# To run the application simply supply the datapath used, for example:
#
# pyhon2.7 dpctl_parser.py unix:/var/run/dp0
#
# Enjoy...
#
# Written by Simhon Doctori.
# For any issues please send reqs to simhond@gmail.com
#
# Regular expression to parse the output
first_parse = re.compile(r'^stat_repl\{type="flow", flags="0x0", stats=\[')
flow_parse = re.compile(r'(\{table="[0-9]+",\s?match="oxm\{[.A-Fa-z\s?+,"0-9:=_-]+\}",\s?dur_s="[0-9]+",\s?dur_ns="[0-9]+",\s?prio="[0-9]+",\s?idle_to="[0-9]+",\s?hard_to="[0-9]+",\s?cookie="0x[0-9a-fA-F]+",\s?pkt_cnt="[0-9]+",\s?byte_cnt="[0-9]+",\s?insts=\[((apply\{acts=\[[A-Fa-z,\s\{\}"0-9:\.=_-]*\]\})?(write\{acts=\[[A-Fa-z,\s\{\}"0-9:\.=_-]*\]\})?(,\s)?(meta\{meta="0x[0-9a-fA-F]+", mask="0x[0-9a-fA-F]+"\})?(,\s)?(goto\{table="[0-9]+"\})?)\]\})+')
flow_parse_values = re.compile(r'(\{table="(?P<table>[0-9]+)",\s?match="oxm\{(?P<match>[A-Fa-z,\s\?+,"0-9:\.=_-]+)\}",\s?dur_s="(?P<dur_s>[0-9]+)",\s?dur_ns="(?P<dur_ns>[0-9]+)",\s?prio="(?P<prio>[0-9]+)",\s?idle_to="(?P<idle_to>[0-9]+)",\s?hard_to="[0-9]+",\s?cookie="(?P<cookie>0x[0-9a-fA-F]+)",\s?pkt_cnt="(?P<pkts>[0-9]+)",\s?byte_cnt="(?P<bytes>[0-9]+)",\s?insts=\[(?P<insts>(apply\{acts=\[[A-Fa-z,\s\{\}"0-9:\.=_-]*\]\})?(write\{acts=\[[A-Fa-z,\s\{\}"0-9:\.=_-]*\]\})?(,\s)?(meta\{meta="0x[0-9a-fA-F]+", mask="0x[0-9a-fA-F]+"\})?(,\s)?(goto\{table="[0-9]+"\})?)\]\})+')
                                                                                                                                                                                                                                                                                                                                                                       


def process_flow (ix,flow):
    new_flow = {} 
    if flow_parse_values.match(flow):
        new_flow['table'] = flow_parse_values.search(flow).group('table')
        new_flow['match'] = flow_parse_values.search(flow).group('match')
        new_flow['dur_s'] = flow_parse_values.search(flow).group('dur_s')
        new_flow['prio'] = flow_parse_values.search(flow).group('prio')
        new_flow['dur_ns'] = flow_parse_values.search(flow).group('dur_ns')
        new_flow['idle_to'] = flow_parse_values.search(flow).group('idle_to')
        new_flow['cookie'] = flow_parse_values.search(flow).group('cookie')
        new_flow['pkts'] = flow_parse_values.search(flow).group('pkts')
        new_flow['bytes'] = flow_parse_values.search(flow).group('bytes')
        new_flow['insts'] = flow_parse_values.search(flow).group('insts')
    #print 'Flow {0} ->'.format(ix),new_flow
    return new_flow

        

def do_parse(line):
    print 'received input is:'
    #print line
    print '\nstart parsing...'
    m = first_parse.match(line)
    if m:
        new_str = line[m.end():len(line)-2]
        #print 'new str:',new_str
        #print 'findall:',flow_parse.findall(new_str)
        cnt = 0
        for x in flow_parse.findall(new_str):
            cnt += 1
            #print 'entry number {0} :\n'.format(cnt),x[0]
            flow_lists.extend([process_flow(cnt,x[0])])
    else:
        print 'match not found'


def parse_list():
    last_table_id = -1
    for x in flow_lists:
        table_id = x['table']
        if table_to_parse!=-1 and table_to_parse!=table_id:
            continue
        if last_table_id<table_id:
            print '\n+-+-+-+-+ Table-{0} +-+-+-+-+'.format(table_id)
            last_table_id = table_id
        print '-------------------'
        print 'FLOW: priority: {0}, duration: {1}sec ({2}nsec), idle_to: {3}, cookie: {4}, pkts: {5}, bytes: {6}.'.format(x['prio'],
              x['dur_s'],x['dur_ns'],x['idle_to'],x['cookie'],x['pkts'],x['bytes']) 
        print 'MATCH: ',x['match']
        print 'INSTRUCTION: ',x['insts']
    print '-------------------'
        

flow_lists = []

if len(sys.argv)<=1 :
    print 'Please supply the datapath to use - example \'unix:/var/run/dp0\''
    sys.exit()

table_to_parse = -1
datapath = sys.argv[1]
if len(sys.argv)==3 :
    table_to_parse = sys.argv[2]
print 'running command :'
os.system("dpctl "+datapath+" stats-flow > ./dpctl_output")
#print 'parsing the output file'

with open("./dpctl_output") as f:
    for line in f:
	if 'stat_repl' in line:
		do_parse(line)
parse_list()
#print 'delete the output file'
os.system("rm -rf ./dpctl_output")
print '\n\nExit'
