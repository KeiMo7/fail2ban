# emacs: -*- mode: python; py-indent-offset: 4; indent-tabs-mode: t -*-
# vi: set ft=python sts=4 ts=4 sw=4 noet :

"""Reproducible 20k-ban batch/atomic-chain benchmark.

This measures the fail2ban control plane with an in-process firewall model.
It is intentionally dependency-free and safe to run without root.  The
model exposes the same two operations as the iptables-batch action:

* build a complete candidate rule set;
* atomically replace the active set only after the build succeeds.

Run with:
    python3 -m fail2ban.tests.batchbenchmark
"""

from __future__ import print_function

import argparse
import json
import logging
import threading
import time

from ..server.action import ActionBase
from .dummyjail import DummyJail


class AtomicChain(ActionBase):

	def __init__(self, jail, name, per_item_delay=0.0002,
			batch_delay_per_entry=0.00002, batch_delay_min=0.2):
		super(AtomicChain, self).__init__(jail, name)
		self.per_item_delay = per_item_delay
		self.batch_delay_per_entry = batch_delay_per_entry
		self.batch_delay_min = batch_delay_min
		self.lock = threading.Lock()
		self.active = set()
		self.fail_next_batch = False
		self.batch_calls = 0
		self.single_calls = 0

	def start(self):
		return True

	def stop(self):
		return True

	def ban(self, aInfo):
		self.single_calls += 1
		time.sleep(self.per_item_delay)
		with self.lock:
			self.active.add(str(aInfo['ip']))

	def _banMany(self, aInfos):
		self.batch_calls += 1
		candidate = set(str(aInfo['ip']) for aInfo in aInfos)
		time.sleep(max(self.batch_delay_min,
			len(candidate) * self.batch_delay_per_entry))
		if self.fail_next_batch:
			self.fail_next_batch = False
			raise RuntimeError('simulated iptables-restore failure')
		with self.lock:
			self.active = candidate

	@property
	def _has_batch_ban(self):
		return True

	def unban(self, aInfo):
		time.sleep(self.per_item_delay)
		with self.lock:
			self.active.discard(str(aInfo['ip']))

	def reban(self, aInfo):
		return self.ban(aInfo)


def _build_actions(batch, count, per_item_delay, batch_delay):
	jail = DummyJail()
	actions = jail.actions
	chain = AtomicChain(jail, 'bench',
		per_item_delay=per_item_delay,
		batch_delay_per_entry=batch_delay / max(1, count))
	actions._actions['bench'] = chain
	if batch:
		actions.setBanBatch(True, size=count + 1, timeout=10)
	return jail, actions, chain


def _ips(start, count):
	"""Generate deterministic non-overlapping documentation-safe IPs."""
	return ['10.%d.%d.%d' % ((n >> 16) & 255, (n >> 8) & 255, n & 255)
		for n in range(start, start + count)]


def run(count=20000, per_item_delay=0.0002, batch_build_delay=0.5):
	logging.getLogger('fail2ban').setLevel(logging.CRITICAL)
	result = {'count': count}

	# Existing path: one action call per ticket.
	_, actions, chain = _build_actions(
		False, count, per_item_delay, batch_build_delay)
	initial = _ips(1, count)
	started = time.time()
	actions.addBannedIP(initial)
	result['per_item_seconds'] = round(time.time() - started, 3)
	result['per_item_action_calls'] = chain.single_calls

	# Batched path: the complete chain is built and switched once.
	_, actions, chain = _build_actions(
		True, count, per_item_delay, batch_build_delay)
	started = time.time()
	actions.addBannedIP(initial)
	result['batch_initial_seconds'] = round(time.time() - started, 3)
	result['batch_action_calls'] = chain.batch_calls
	result['batch_initial_entries'] = len(chain.active)

	# A second batch rebuilds the complete 20k chain while traffic probes
	# the previously active chain.  Any observed missing ban is a release
	# during reload.
	known = set(chain.active)
	misses = [0]
	checks = [0]
	stop = threading.Event()
	def probe():
		while not stop.is_set():
			with chain.lock:
				current = chain.active
				checks[0] += 1
				if not known.issubset(current):
					misses[0] += 1
			time.sleep(0.0005)
	prober = threading.Thread(target=probe)
	prober.start()
	started = time.time()
	actions.flushBanBatch()
	# Force a full rebuild by adding one new address.
	actions.addBannedIP(_ips(count + 1, 1))
	result['batch_reload_seconds'] = round(time.time() - started, 3)
	stop.set()
	prober.join()
	result['reload_probe_checks'] = checks[0]
	result['reload_released_connections'] = misses[0]

	# Failed build must leave the active chain byte-for-byte equivalent.
	before = set(chain.active)
	chain.fail_next_batch = True
	actions._batch_fallback = False
	actions.addBannedIP(_ips(count + 2, 1))
	with chain.lock:
		result['failed_batch_preserved_chain'] = before == chain.active

	# Incremental unban removes exactly one entry.
	victim = initial[0]
	before = set(chain.active)
	actions.removeBannedIP(victim)
	with chain.lock:
		after = set(chain.active)
	result['unban_single_removed'] = len(before - after) == 1 and victim not in after
	result['unban_expected_chain'] = after == (before - {victim})
	result['final_entries'] = len(after)
	return result


def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('-n', '--count', type=int, default=20000)
	parser.add_argument('--per-item-delay', type=float, default=0.0002)
	parser.add_argument('--batch-build-delay', type=float, default=0.5)
	args = parser.parse_args()
	print(json.dumps(run(args.count, args.per_item_delay,
		args.batch_build_delay), indent=2, sort_keys=True))


if __name__ == '__main__':
	main()
