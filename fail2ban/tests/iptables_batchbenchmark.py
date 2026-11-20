# emacs: -*- mode: python; py-indent-offset: 4; indent-tabs-mode: t -*-
# vi: set ft=python sts=4 ts=4 sw=4 noet :

"""Real-kernel iptables acceptance benchmark.

Run inside an isolated user/network namespace (no root required):

    unshare -Urn python3 -m fail2ban.tests.iptables_batchbenchmark

The namespace gives CAP_NET_ADMIN without touching the host firewall.  The
script builds two 20,000-rule generations, performs packet-level connection
probes during an atomic reload, injects a failed iptables-restore, and checks
that unban removes exactly one rule.
"""

from __future__ import print_function

import argparse
import json
import logging
import os
import shutil
import socket
import subprocess
import threading
import time

from ..client.actionreader import ActionReader
from ..server.action import CommandAction
from .dummyjail import DummyJail


DISPATCH = 'f2b-bench'
GEN_A = 'f2b-bench-a'
GEN_B = 'f2b-bench-b'


def run_cmd(args, input_text=None, check=True):
	proc = subprocess.run(args, input=input_text, text=True,
		stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	if check and proc.returncode:
		raise RuntimeError('%s failed (%d): %s' % (
			' '.join(args), proc.returncode, proc.stderr.strip()))
	return proc


def iptables(*args, **kwargs):
	return run_cmd(['iptables', '-w'] + list(args), **kwargs)


def _ips(count):
	for n in range(1, count + 1):
		yield '10.%d.%d.%d' % ((n >> 16) & 255, (n >> 8) & 255, n & 255)


def chain_has(chain, ip, target):
	proc = iptables('-C', chain, '-s', ip, '-j', *target, check=False)
	return proc.returncode == 0


def chain_rule_count(chain):
	proc = iptables('-S', chain)
	return sum(1 for line in proc.stdout.splitlines()
		if line.startswith('-A '))


def setup():
	cleanup()


def load_action(port):
	reader = ActionReader('iptables-batch', 'bench',
		{'name': 'bench', 'port': str(port)}, basedir='config')
	if not reader.read():
		raise RuntimeError('unable to read iptables-batch action')
	reader.getOptions({})
	opts = reader.getCombined(
		ignore=CommandAction._escapedTags | set(('timeout', 'bantime')))
	action = CommandAction(DummyJail('bench'), 'bench')
	for key in (
			'actionstart', 'actioncheck', 'actionrepair', 'actionbatchban',
			'actionban', 'actionunban', 'actionstop', 'actionflush',
			'iptables', 'iptables-restore', 'name', 'blocktype', 'chain',
			'port', 'protocol', 'lockingopt', 'returntype', 'batchchunksize',
			'pre-rule', 'rule-jump', 'type'):
		if key in opts:
			setattr(action, key, opts[key])
	if not action.start():
		raise RuntimeError('unable to start iptables-batch action')
	return action


def cleanup():
	iptables('-D', 'INPUT', '-j', DISPATCH, check=False)
	for chain in (DISPATCH, GEN_A, GEN_B):
		iptables('-F', chain, check=False)
		iptables('-X', chain, check=False)


class ProbeServer(object):

	def __init__(self):
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.sock.bind(('127.0.0.1', 0))
		self.sock.listen(128)
		self.sock.settimeout(0.1)
		self.port = self.sock.getsockname()[1]
		self.active = True
		self.thread = threading.Thread(target=self._accept)
		self.thread.start()

	def _accept(self):
		while self.active:
			try:
				conn, _ = self.sock.accept()
				conn.close()
			except socket.timeout:
				continue
			except OSError:
				break

	def connect_allowed(self, timeout=0.03):
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		try:
			sock.bind(('127.0.0.1', 0))
			sock.settimeout(timeout)
			return sock.connect_ex(('127.0.0.1', self.port)) == 0
		except (socket.timeout, OSError):
			return False
		finally:
			sock.close()

	def close(self):
		self.active = False
		self.sock.close()
		self.thread.join()


def run(count=20000):
	if os.name != 'posix' or not shutil.which('iptables'):
		raise RuntimeError('iptables is required')
	logging.getLogger('fail2ban').setLevel(logging.CRITICAL)
	setup()
	server = ProbeServer()
	action = None
	result = {'count': count}
	try:
		action = load_action(server.port)
		infos = [{'family': 'inet4', 'ip': ip} for ip in _ips(count)]
		# Initial complete generation and first dispatcher jump.
		started = time.time()
		action._banMany(infos)
		result['initial_build_seconds'] = round(time.time() - started, 3)

		# Verify probes are meaningful: a banned loopback source must be
		# blocked while the active generation is A.
		result['banned_probe_blocked'] = not server.connect_allowed()
		if not result['banned_probe_blocked']:
			raise RuntimeError('packet probe did not observe the DROP rule')

		# Build B while A remains active.  Count successful probes; these
		# are connections that escaped a known ban during the reload.
		attempts = [0]
		allowed = [0]
		stop = threading.Event()
		def probe():
			while not stop.is_set():
				attempts[0] += 1
				if server.connect_allowed():
					allowed[0] += 1
		prober = threading.Thread(target=probe)
		prober.start()
		started = time.time()
		action._banMany(infos)
		result['reload_seconds'] = round(time.time() - started, 3)
		stop.set()
		prober.join()
		result['reload_probe_attempts'] = attempts[0]
		result['reload_released_connections'] = allowed[0]

		# Injected restore failure must not change the dispatcher.
		before = iptables('-S', DISPATCH).stdout
		old_blocktype = action.blocktype
		action.blocktype = 'F2B_INVALID_TARGET'
		try:
			try:
				action._banMany(infos)
			except RuntimeError:
				pass
			else:
				raise RuntimeError('injected iptables failure was not observed')
		finally:
			action.blocktype = old_blocktype
		after = iptables('-S', DISPATCH).stdout
		result['failed_batch_preserved_chain'] = before == after

		# One unban removes exactly one entry from the active generation.
		victim = '10.0.0.1'
		peer = '10.0.0.2'
		active = GEN_B if iptables('-C', DISPATCH, '-j', GEN_B,
			check=False).returncode == 0 else GEN_A
		expected = chain_rule_count(active)
		action.unban({'family': 'inet4', 'ip': victim})
		target = action.blocktype.split()
		result['unban_single_removed'] = (
			not chain_has(active, victim, target) and
			chain_has(active, peer, target))
		result['unban_expected_chain'] = (
			chain_rule_count(active) == expected - 1)
		result['final_entries'] = chain_rule_count(active)
		result['dispatcher_active_generation'] = active.replace(
			'f2b-bench-', '').upper()
		return result
	finally:
		server.close()
		if action is not None:
			try:
				action._stop()
			except Exception:
				pass
		cleanup()


def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('-n', '--count', type=int, default=20000)
	args = parser.parse_args()
	print(json.dumps(run(args.count), indent=2, sort_keys=True))


if __name__ == '__main__':
	main()
