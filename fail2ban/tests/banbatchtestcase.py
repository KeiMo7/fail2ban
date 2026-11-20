# emacs: -*- mode: python; py-indent-offset: 4; indent-tabs-mode: t -*-
# vi: set ft=python sts=4 ts=4 sw=4 noet :

from __future__ import absolute_import

import os
import tempfile

from ..server.actions import Actions
from ..server.database import Fail2BanDb
from ..server.filter import Filter
from ..server.ticket import FailTicket
from .dummyjail import DummyJail
from .utils import LogCaptureTestCase


class BatchActionsTest(LogCaptureTestCase):

	def setUp(self):
		super(BatchActionsTest, self).setUp()
		self.jail = DummyJail()
		self.actions = self.jail.actions
		self.actions.add('batch')
		self.action = self.actions['batch']
		self.action.actionstart = ''
		self.action.actioncheck = ''
		self.action.actionban = 'echo single <ip>'
		self.action.actionbatchban = 'echo batch <ip-count> <ip-list>'
		self.action.actionunban = 'echo unban <ip>'
		self.action.actionstop = ''
		self.action.actionflush = ''

	def tearDown(self):
		if self.actions.isAlive():
			self.actions.stop()
			self.actions.join()
		self.actions.stopActions()
		super(BatchActionsTest, self).tearDown()

	def testBatchUsesOneBulkCommand(self):
		self.actions.setBanBatch(True, size=100, timeout=5)
		ips = ['192.0.2.1', '192.0.2.2', '192.0.2.3']
		self.assertEqual(self.actions.addBannedIP(ips), 3)
		self.assertLogged('batch 3 192.0.2.1 192.0.2.2 192.0.2.3', wait=True)
		self.assertNotLogged('single 192.0.2.1')
		stats = self.actions.getBanStatistics()
		self.assertEqual(stats['batch']['dispatches'], 1)
		self.assertEqual(stats['batch']['entries'], 3)
		self.assertEqual(stats['latency']['count'], 3)

	def testBatchFailureFallsBackPerTicket(self):
		self.action.actionbatchban = 'exit 1'
		self.actions.setBanBatch(True, size=100, timeout=5, fallback=True)
		self.assertEqual(self.actions.addBannedIP(['192.0.2.1', '192.0.2.2']), 2)
		self.assertLogged('single 192.0.2.1', 'single 192.0.2.2', all=True, wait=True)
		stats = self.actions.getBanStatistics()
		self.assertEqual(stats['batch']['failures'], 1)
		self.assertEqual(stats['batch']['fallback_entries'], 2)
		self.assertEqual(stats['batch']['failed_entry_count'], 2)
		self.assertEqual(stats['failed'], [])

	def testBatchRebuildContainsAllCurrentBans(self):
		self.actions.setBanBatch(True, size=100, timeout=5)
		self.actions.addBannedIP('192.0.2.1')
		self.assertLogged('batch 1 192.0.2.1', wait=True)
		self.pruneLog()
		self.actions.addBannedIP('192.0.2.2')
		self.assertLogged('batch 2 192.0.2.1 192.0.2.2', wait=True)

	def testBatchCoalescesShortWindowFromQueue(self):
		self.actions.setBanBatch(True, size=100, timeout=0.2)
		self.actions.start()
		for ip in ('192.0.2.1', '192.0.2.2', '192.0.2.3'):
			self.jail.putFailTicket(FailTicket(ip))
		self.assertLogged('batch 3 ', wait=True)
		self.actions.stop()
		self.actions.join()

	def testDefaultRemainsPerTicket(self):
		self.assertEqual(self.actions.addBannedIP(['192.0.2.1', '192.0.2.2']), 2)
		self.assertLogged('single 192.0.2.1', 'single 192.0.2.2', all=True, wait=True)
		self.assertNotLogged('batch 2')
		self.assertEqual(self.actions.getBanBatch()['enabled'], False)

	def testUnbanOnlyDeletesSingleRule(self):
		self.actions.setBanBatch(True, size=100, timeout=5)
		self.actions.addBannedIP(['192.0.2.1', '192.0.2.2'])
		self.pruneLog()
		self.assertEqual(self.actions.removeBannedIP('192.0.2.1'), 1)
		self.assertLogged('unban 192.0.2.1', wait=True)
		self.assertNotLogged('batch 1')

	def testExactCidrCompaction(self):
		values = ['192.0.2.%d' % i for i in range(256)]
		self.assertEqual(Actions._compactAddresses(values), ['192.0.2.0/24'])
		self.assertEqual(
			Actions._compactAddresses(['192.0.2.1', '192.0.2.2']),
			['192.0.2.1/32', '192.0.2.2/32'])


class WhitelistAuditTest(LogCaptureTestCase):

	def setUp(self):
		super(WhitelistAuditTest, self).setUp()
		self.jail = DummyJail()
		self.flt = Filter(self.jail)
		self.jail._Jail__filter = self.flt
		self.db = Fail2BanDb(os.path.join(
			tempfile.mkdtemp(prefix='f2b-test-'), 'test.db'))
		self.jail.database = self.db

	def tearDown(self):
		self.jail.database = None
		self.db.close()
		super(WhitelistAuditTest, self).tearDown()

	def testWhitelistSourceIsRetainedAndBlocksBan(self):
		self.flt.addIgnoreIP('192.0.2.1', source='ops', reason='false positive')
		self.flt.addIgnoreIP('192.0.2.1', source='monitor')
		self.assertEqual(
			self.flt.getIgnoreIPStats(), {'ops': 1, 'monitor': 1})
		self.assertEqual(self.jail.actions.addBannedIP('192.0.2.1'), 0)
		self.flt.delIgnoreIPSource('192.0.2.1', 'ops')
		self.assertTrue(self.flt.inIgnoreIPList('192.0.2.1'))
		self.flt.delIgnoreIPSource('192.0.2.1', 'monitor')
		self.assertFalse(self.flt.inIgnoreIPList('192.0.2.1'))

	def testWhitelistAndAuditPersist(self):
		self.db.addWhitelist('192.0.2.1', source='ops',
			reason='shared egress', actor='alice')
		self.assertEqual(self.db.getWhitelist()[0]['source'], 'ops')
		self.db.addAudit('ban', ip='192.0.2.1', jail='sshd',
			actor='alice', reason='test')
		audit = self.db.getAudit(ip='192.0.2.1')
		self.assertEqual(audit[0]['action'], 'ban')
		self.assertEqual(audit[0]['actor'], 'alice')

	def testPersistedWhitelistRestoresIntoFilter(self):
		self.db.addWhitelist('192.0.2.9', source='partner',
			reason='partner egress', actor='bob')
		self.jail.restoreWhitelist()
		self.assertEqual(self.flt.getIgnoreIPStats(), {'partner': 1})
		self.assertTrue(self.flt.inExplicitWhitelist('192.0.2.9'))
