#!/usr/bin/env python2
#-*- coding: utf-8 -*-
from __future__ import print_function

import itertools as it, operator as op, functools as ft
from xml.etree import ElementTree
from io import BytesIO
from datetime import datetime
from collections import namedtuple, defaultdict
import os, sys, logging, re, glob, errno, socket

from nfct_cffi import NFCT

FlowData = namedtuple('FlowData', 'ts proto src dst sport dport mark')

def parse_event(ev_xml):
	etree = ElementTree.parse(BytesIO(ev_xml))

	flow = next(etree.iter())
	assert flow.attrib['type'] == 'new', ev_xml

	ts = flow.find('when')
	ts = datetime(*(int(ts.find(k).text) for k in ['year', 'month', 'day', 'hour', 'min', 'sec']))
	mark = 0

	flow_data = dict()
	for meta in flow.findall('meta'):
		if meta.attrib['direction'] == 'independent':
			mark_node = meta.find('mark')
			if mark_node is not None:
				mark = mark_node.text
	for meta in flow.findall('meta'):
		if meta.attrib['direction'] in ['original', 'reply']:
			l3, l4 = it.imap(meta.find, ['layer3', 'layer4'])
			proto = l3.attrib['protoname'], l4.attrib['protoname']
			if proto[1] not in ['tcp', 'udp']: return
			proto = '{}/{}'.format(*proto)
			src, dst = (l3.find(k).text for k in ['src', 'dst'])
			sport, dport = (int(l4.find(k).text) for k in ['sport', 'dport'])
			flow_data[meta.attrib['direction']] = FlowData(ts, proto, src, dst, sport, dport, mark)

	# Fairly sure all new flows should be symmetrical, check that
	fo, fr = op.itemgetter('original', 'reply')(flow_data)
	assert fo.proto == fr.proto\
		and fo.src == fr.dst and fo.dst == fr.src\
		and fo.sport == fr.dport and fo.dport == fr.sport,\
		flow_data

	return flow_data['original']


def parse_ipv4(enc):
	return socket.inet_ntop(socket.AF_INET, ''.join(reversed(enc.decode('hex'))))

def parse_ipv6( enc,
		_endian=op.itemgetter(*(slice(n*2, (n+1)*2) for n in [6, 7, 4, 5, 2, 3, 0, 1])) ):
	return socket.inet_ntop( socket.AF_INET6,
		''.join(_endian(''.join(reversed(enc.decode('hex'))))) )

def main(argv=None):
	import argparse
	parser = argparse.ArgumentParser(description='conntrack event processor.')
	parser.add_argument('-p', '--protocol',
		help='Regexp (python) filter to match "ev.proto". Examples: ipv4, tcp, ipv6/udp.')
	parser.add_argument('-t', '--format-ts', default='%s',
		help='Timestamp format, as for datetime.strftime() (default: %(default)s).')
	parser.add_argument('-f', '--format',
		default='{ts}: {ev.proto} {ev.src}/{ev.sport} > {ev.dst}/{ev.dport}'
			' :: {info.pid} {info.uid}:{info.gid} {info.service} :: {info.cmdline}',
		help='Output format for each new flow, as for str.format() (default: %(default)s).')
	parser.add_argument('--debug',
		action='store_true', help='Verbose operation mode.')
	opts = parser.parse_args(argv or sys.argv[1:])

	opts.format += '\n'

	import logging
	logging.basicConfig(level=logging.DEBUG if opts.debug else logging.WARNING)
	global log
	log = logging.getLogger()

	nfct = NFCT()

	# I have no idea why, but unless I init "all events" conntrack
	#  socket once after boot, no events ever make it past NFNLGRP_CONNTRACK_NEW.
	# So just get any event here jic and then init proper handlers.
	src = nfct.generator()
	next(src)
	try: src.send(StopIteration)
	except StopIteration: pass

	src = nfct.generator(events=nfct.libnfct.NFNLGRP_CONNTRACK_NEW)
	netlink_fd = next(src) # can be polled, but not used here

	log.debug('Started logging')
	for ev_xml in src:
		try: ev = parse_event(ev_xml)
		except:
			log.error('Failed to parse event data: {0}'.format(ev_xml))
			log.error('Inner Exception: {0}'.format(sys.exc_info()))
			continue
		if not ev: continue
		if opts.protocol and not re.search(opts.protocol, ev.proto): continue
		log.debug('Event: {0}'.format(ev))
		sys.stdout.write(opts.format.format( ev=ev,
			#ts=ev.ts.strftime(opts.format_ts), info=get_flow_info(ev) ))
			ts=ev.ts.strftime(opts.format_ts) ))
		sys.stdout.flush()


if __name__ == '__main__': sys.exit(main())
