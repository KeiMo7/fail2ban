# emacs: -*- mode: python; py-indent-offset: 4; indent-tabs-mode: t -*-
# vi: set ft=python sts=4 ts=4 sw=4 noet :

# This file is part of Fail2Ban.
#
# Fail2Ban is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Fail2Ban is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Fail2Ban; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

# Author: Cyril Jaquier
# 

__author__ = "Cyril Jaquier"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

import logging
import os
import sys
import time
import ipaddress
from threading import RLock
try:
	from collections.abc import Mapping
except ImportError:
	from collections import Mapping
from collections import OrderedDict

from .banmanager import BanManager, BanTicket
from .ipdns import IPAddr
from .jailthread import JailThread
from .action import ActionBase, CommandAction, CallingMap
from .mytime import MyTime
from .observer import Observers
from .utils import Utils
from ..helpers import getLogger

# Gets the instance of the logger.
logSys = getLogger(__name__)


class Actions(JailThread, Mapping):
	"""Handles jail actions.

	This class handles the actions of the jail. Creation, deletion or to
	actions must be done through this class. This class is based on the
	Mapping type, and the `add` method must be used to add new actions.
	This class also starts and stops the actions, and fetches bans from
	the jail executing these bans via the actions.

	Parameters
	----------
	jail: Jail
		The jail of which the actions belongs to.

	Attributes
	----------
	daemon
	ident
	name
	status
	active : bool
		Control the state of the thread.
	idle : bool
		Control the idle state of the thread.
	sleeptime : int
		The time the thread sleeps for in the loop.
	"""

	def __init__(self, jail):
		JailThread.__init__(self, name="f2b/a."+jail.name)
		## The jail which contains this action.
		self._jail = jail
		self._actions = OrderedDict()
		## The ban manager.
		self.banManager = BanManager()
		self.banEpoch = 0
		## Serializes queue processing with manual ban/unban calls.
		self._ban_lock = RLock()
		## Optional batched dispatch (disabled by default).
		self._batch_enabled = False
		self._batch_size = 100
		self._batch_timeout = 1.0
		self._batch_fallback = True
		self._batch_tickets = []
		self._batch_deadline = None
		self._rebuilding_actions = set()
		self._chain_max = 0
		self._chain_overflow = 'aggregate'
		self._chain_aggregated = False
		## Runtime counters used by status and operational dashboards.
		self._ban_metrics = {
			'unbanned': 0,
			'batch_dispatches': 0,
			'batch_entries': 0,
			'batch_failures': 0,
			'fallback_entries': 0,
			'latency_count': 0,
			'latency_total': 0.0,
			'latency_max': 0.0,
		}
		self._ban_by_action = dict()
		self._failed_bans = []
		self._failed_batch_entries = []
		self.__lastConsistencyCheckTM = 0
		## Precedence of ban (over unban), so max number of tickets banned (to call an unban check):
		self.banPrecedence = 10
		## Max count of outdated tickets to unban per each __checkUnBan operation:
		self.unbanMaxCount = self.banPrecedence * 2

	@staticmethod
	def _load_python_module(pythonModule):
		mod = Utils.load_python_module(pythonModule)
		if not hasattr(mod, "Action"): # pragma: no cover
			raise RuntimeError(
				"%s module does not have 'Action' class" % pythonModule)
		elif not issubclass(mod.Action, ActionBase): # pragma: no cover
			raise RuntimeError(
				"%s module %s does not implement required methods" % (
					pythonModule, mod.Action.__name__))
		return mod


	def add(self, name, pythonModule=None, initOpts=None, reload=False):
		"""Adds a new action.

		Add a new action if not already present, defaulting to standard
		`CommandAction`, or specified Python module.

		Parameters
		----------
		name : str
			The name of the action.
		pythonModule : str, optional
			Path to Python file which must contain `Action` class.
			Default None, which means `CommandAction` is used.
		initOpts : dict, optional
			Options for Python Action, used as keyword arguments for
			initialisation. Default None.

		Raises
		------
		ValueError
			If action name already exists.
		RuntimeError
			If external Python module does not have `Action` class
			or does not implement necessary methods as per `ActionBase`
			abstract class.
		"""
		# Check is action name already exists
		if name in self._actions:
			if not reload:
				raise ValueError("Action %s already exists" % name)
			# keep existing action (no new instance, no start/stop), don't execute reload
			# right now, reload after all parameters are actualized:
			action = self._actions[name]
			if hasattr(action, 'clearAllParams'):
				action.clearAllParams()
			self._reload_actions[name] = (False, initOpts)
			return
		## Create new action:
		if pythonModule is None:
			action = CommandAction(self._jail, name)
		else:
			customActionModule = self._load_python_module(pythonModule)
			action = customActionModule.Action(self._jail, name, **initOpts)
		self._actions[name] = action
		if reload:
			self._reload_actions[name] = (True, initOpts)
	def reload(self, begin=True):
		""" Begin or end of reloading resp. refreshing of all parameters
		"""
		if begin:
			self._reload_actions = dict()
		else:
			if hasattr(self, '_reload_actions'):
				# reload actions after all parameters set via stream:
				for name, (startNewAct, initOpts) in self._reload_actions.items():
					if name in self._actions:
						if startNewAct:
							try:
								self._actions[name].start()
							except Exception as e:
								logSys.error("Failed to start jail '%s' action '%s': %s",
									self._jail.name, name, e,
									exc_info=logSys.getEffectiveLevel()<=logging.DEBUG)
						elif hasattr(self._actions[name], 'reload'):
							self._actions[name].reload(**(initOpts if initOpts else {}))
						else:
							logSys.info("Jail '%s' action '%s' does not support reload, changed "
								"parameters take effect after restart of the jail", self._jail.name, name)
				# remove obsolete actions (untouched by reload process):
				delacts = OrderedDict((name, action) for name, action in self._actions.items()
					if name not in self._reload_actions)
				if len(delacts):
					# unban all tickets using removed actions only:
					self.__flushBan(db=False, actions=delacts, stop=True)
					# stop and remove it:
					self.stopActions(actions=delacts)
				delattr(self, '_reload_actions')

	def __getitem__(self, name):
		try:
			return self._actions[name]
		except KeyError:
			raise KeyError("Invalid Action name: %s" % name)

	def __delitem__(self, name):
		try:
			del self._actions[name]
		except KeyError:
			raise KeyError("Invalid Action name: %s" % name)

	def __iter__(self):
		return iter(self._actions)

	def __len__(self):
		return len(self._actions)

	def __eq__(self, other): # Required for Threading
		return False

	def __hash__(self): # Required for Threading
		return id(self)

	##
	# Set the ban time.
	#
	# @param value the time
	
	def setBanTime(self, value):
		value = MyTime.str2seconds(value)
		self.banManager.setBanTime(value)
		logSys.info("  banTime: %s" % value)
	
	##
	# Get the ban time.
	#
	# @return the time
	
	def getBanTime(self):
		return self.banManager.getBanTime()

	def setBanBatch(self, enabled, size=None, timeout=None, fallback=None):
		"""Configure optional batched ban dispatch.

		Batching is disabled by default.  When enabled, tickets collected
		during ``timeout`` seconds (or up to ``size`` entries) are sent to
		batch-capable actions through a single ``banMany`` call.
		"""
		self._batch_enabled = self._asBool(enabled)
		if size is not None:
			self._batch_size = max(1, int(size))
		if timeout is not None:
			self._batch_timeout = max(0.0, float(timeout))
		if fallback is not None:
			self._batch_fallback = self._asBool(fallback)
		if not self._batch_enabled:
			self.flushBanBatch()
		return self.getBanBatch()

	@staticmethod
	def _asBool(value):
		if isinstance(value, str):
			return value.strip().lower() in ('1', 'yes', 'true', 'on', 'enabled')
		return bool(value)

	@staticmethod
	def _compactAddresses(values):
		"""Return an exact, minimal CIDR representation of address values."""
		by_family = {4: [], 6: []}
		for value in values:
			text = str(value)
			try:
				net = ipaddress.ip_network(text, strict=False)
			except ValueError:
				continue
			by_family[net.version].append(
				(int(net.network_address), int(net.broadcast_address)))
		result = []
		for version, ranges in by_family.items():
			if not ranges:
				continue
			ordered = sorted(ranges)
			start, prev = ordered[0]
			merged = []
			for first, last in ordered[1:]:
				if first <= prev + 1:
					prev = max(prev, last)
					continue
				merged.append((start, prev))
				start, prev = first, last
			merged.append((start, prev))
			for first, last in merged:
				first = ipaddress.ip_address(first) if version == 6 \
					else ipaddress.IPv4Address(first)
				last = ipaddress.ip_address(last) if version == 6 \
					else ipaddress.IPv4Address(last)
				for net in ipaddress.summarize_address_range(first, last):
					result.append(str(net))
		return result

	def _batchActionInfos(self, action, infos):
		"""Apply exact chain-size compaction for bulk-capable actions."""
		if not self._chain_max or len(infos) <= self._chain_max:
			self._chain_aggregated = False
			return infos
		if self._chain_overflow == 'warn':
			logSys.warning(
				"[%s] chain size %d exceeds limit %d (overflow action: warn)",
				self._jail.name, len(infos), self._chain_max)
			self._chain_aggregated = False
			return infos
		addresses = [aInfo['ip'] for aInfo in infos]
		compacted = self._compactAddresses(addresses)
		if not compacted or len(compacted) >= len(infos):
			logSys.warning(
				"[%s] chain size %d exceeds limit %d and cannot be compacted",
				self._jail.name, len(infos), self._chain_max)
			self._chain_aggregated = False
			return infos
		self._chain_aggregated = True
		logSys.warning(
			"[%s] compacted %d bans to %d chain entries (limit %d)",
			self._jail.name, len(infos), len(compacted), self._chain_max)
		if len(compacted) > self._chain_max:
			logSys.error(
				"[%s] chain still exceeds limit after compaction (%d > %d); "
				"configure an ipset/nftables action for this volume",
				self._jail.name, len(compacted), self._chain_max)
		template = infos[0]
		result = []
		for network in compacted:
			info = template.copy()
			info['ip'] = network
			info['family'] = 'inet6' if ':' in network else 'inet4'
			result.append(info)
		return result

	def getBanBatch(self):
		return {
			'enabled': self._batch_enabled,
			'size': self._batch_size,
			'timeout': self._batch_timeout,
			'fallback': self._batch_fallback,
			'pending': len(self._batch_tickets),
		}

	def setBanChainMax(self, value, overflow=None):
		self._chain_max = max(0, int(value))
		if overflow is not None:
			overflow = str(overflow).lower()
			if overflow not in ('aggregate', 'warn'):
				raise ValueError("ban overflow mode must be 'aggregate' or 'warn'")
			self._chain_overflow = overflow
		return self._chain_max

	def getBanChainMax(self):
		return self._chain_max

	def _nextBatchWaitTime(self):
		if not self._batch_deadline:
			return None
		return max(0.0, self._batch_deadline - time.time())

	def getBanned(self, ids):
		lst = self.banManager.getBanList()
		if not ids:
			return lst
		if len(ids) == 1:
			return 1 if ids[0] in lst else 0
		return [1 if ip in lst else 0 for ip in ids]

	def getBanList(self, withTime=False):
		"""Returns the list of banned IP addresses.

		Returns
		-------
		list
			The list of banned IP addresses.
		"""
		return self.banManager.getBanList(ordered=True, withTime=withTime)

	def addBannedIP(self, ip, actor='cli', reason=None, source=None):
		"""Ban an IP or list of IPs."""
		unixTime = MyTime.time()

		if isinstance(ip, list):
			# Multiple IPs:
			tickets = []
			for value in ip:
				ticket = BanTicket(value, unixTime)
				ticket.setData(actor=actor, ban_reason=reason, source=source)
				tickets.append(ticket)
		else:
			# Single IP:
			ticket = BanTicket(ip, unixTime)
			ticket.setData(actor=actor, ban_reason=reason, source=source)
			tickets = (ticket,)

		with self._ban_lock:
			cnt = self.__checkBan(tickets)
			if self._batch_enabled and self._batch_tickets:
				self.flushBanBatch()
		return cnt

	def removeBannedIP(self, ip=None, db=True, ifexists=False,
			actor='cli', reason=None, source=None):
		"""Removes banned IP calling actions' unban method

		Remove a banned IP now, rather than waiting for it to expire,
		even if set to never expire.

		Parameters
		----------
		ip : list, str, IPAddr or None
			The IP address (or multiple IPs as list) to unban or all IPs if None

		Raises
		------
		ValueError
			If `ip` is not banned
		"""
		# Unban all?
		if ip is None:
			return self.__flushBan(db)
		# Multiple IPs:
		if isinstance(ip, (list, tuple)):
			missed = []
			cnt = 0
			for i in ip:
				try:
					cnt += self.removeBannedIP(i, db, ifexists,
						actor=actor, reason=reason, source=source)
				except ValueError:
					if not ifexists:
						missed.append(i)
			if missed:
				raise ValueError("not banned: %r" % missed)
			return cnt
		# Single IP:
		# Always delete ip from database (also if currently not banned)
		if db and self._jail.database is not None:
			self._jail.database.delBan(self._jail, ip)
		# Find the ticket with the IP.
		ticket = self.banManager.getTicketByID(ip)
		if ticket is not None:
			# Unban the IP.
			self.__unBan(ticket)
			self.audit('unban', ip=ticket.getID(), actor=actor,
				reason=reason, source=source)
			# Exact CIDR compaction cannot be edited by deleting one host;
			# atomically rebuild from the remaining bans in this mode.
			if self._chain_aggregated:
				for name, action in self._actions.items():
					if getattr(action, '_has_batch_ban', False):
						self.rebuildAction(action, name)
		else:
			# Multiple IPs by subnet or dns:
			if not isinstance(ip, IPAddr):
				ipa = IPAddr(ip)
				if not ipa.isSingle: # subnet (mask/cidr) or raw (may be dns/hostname):
					ips = list(filter(ipa.contains, self.banManager.getBanList()))
					if ips:
						return self.removeBannedIP(ips, db, ifexists,
							actor=actor, reason=reason, source=source)
			# not found:
			msg = "%s is not banned" % ip
			logSys.log(logging.MSG, msg)
			if ifexists:
				return 0
			raise ValueError(msg)
		return 1


	def stopActions(self, actions=None):
		"""Stops the actions in reverse sequence (optionally filtered)
		"""
		if actions is None:
			actions = self._actions
		for name, action in reversed(list(actions.items())):
			try:
				action.stop()
			except Exception as e:
				logSys.error("Failed to stop jail '%s' action '%s': %s",
					self._jail.name, name, e,
					exc_info=logSys.getEffectiveLevel()<=logging.DEBUG)
			del self._actions[name]
			logSys.debug("%s: action %s terminated", self._jail.name, name)


	def run(self):
		"""Main loop for Threading.

		This function is the main loop of the thread. It checks the jail
		queue and executes commands when an IP address is banned.

		Returns
		-------
		bool
			True when the thread exits nicely.
		"""
		cnt = 0
		for name, action in self._actions.items():
			try:
				action.start()
			except Exception as e:
				logSys.error("Failed to start jail '%s' action '%s': %s",
					self._jail.name, name, e,
					exc_info=logSys.getEffectiveLevel()<=logging.DEBUG)
		while self.active:
			try:
				if self.idle:
					logSys.debug("Actions: enter idle mode")
					Utils.wait_for(lambda: not self.active or not self.idle,
						lambda: False, self.sleeptime)
					logSys.debug("Actions: leave idle mode")
					continue
				# wait for ban (stop if gets inactive, pending ban or unban):
				bancnt = 0
				wt = min(self.sleeptime, self.banManager._nextUnbanTime - MyTime.time())
				batchwt = self._nextBatchWaitTime()
				if batchwt is not None:
					wt = min(wt, batchwt)
				logSys.log(5, "Actions: wait for pending tickets %s (default %s)", wt, self.sleeptime)
				def _hasPendingWork():
					if not self.active or self._jail.hasFailTickets:
						return True
					return bool(self._batch_tickets and self._nextBatchWaitTime() == 0)
				if Utils.wait_for(_hasPendingWork, wt):
					if self.active and self._jail.hasFailTickets:
						bancnt = self.__checkBan()
					if self._batch_tickets and self._nextBatchWaitTime() == 0:
						self.flushBanBatch()
					cnt += bancnt
				# unban if nothing is banned not later than banned tickets >= banPrecedence
				if not bancnt or cnt >= self.banPrecedence:
					if self.active:
						# let shrink the ban list faster
						bancnt *= 2
						logSys.log(5, "Actions: check-unban %s, bancnt %s, max: %s", bancnt if bancnt and bancnt < self.unbanMaxCount else self.unbanMaxCount, bancnt, self.unbanMaxCount)
						self.__checkUnBan(bancnt if bancnt and bancnt < self.unbanMaxCount else self.unbanMaxCount)
					cnt = 0
			except Exception as e: # pragma: no cover
				logSys.error("[%s] unhandled error in actions thread: %s",
					self._jail.name, e,
					exc_info=logSys.getEffectiveLevel()<=logging.DEBUG)

		self.flushBanBatch()
		self.__flushBan(stop=True)
		self.stopActions()
		return True

	class ActionInfo(CallingMap):

		CM_REPR_ITEMS = ("fid", "raw-ticket")

		AI_DICT = {
			"ip":				lambda self: self.__ticket.getIP(),
			"family":   lambda self: self['ip'].familyStr,
			"ip-rev":		lambda self: self['ip'].getPTR(''),
			"ip-host":	lambda self: self['ip'].getHost(),
			"fid":			lambda self: self.__ticket.getID(),
			"failures":	lambda self: self.__ticket.getAttempt(),
			"time":			lambda self: self.__ticket.getTime(),
			"bantime":  lambda self: self._getBanTime(),
			"bancount":  lambda self: self.__ticket.getBanCount(),
			"matches":	lambda self: "\n".join(self.__ticket.getMatches()),
			# to bypass actions, that should not be executed for restored tickets
			"restored":	lambda self: (1 if self.__ticket.restored else 0),
			# extra-interpolation - all match-tags (captured from the filter):
			"F-*":			lambda self, tag=None: self.__ticket.getData(tag),
			# merged info:
			"ipmatches":			lambda self: "\n".join(self._mi4ip(True).getMatches()),
			"ipjailmatches":	lambda self: "\n".join(self._mi4ip().getMatches()),
			"ipfailures":			lambda self: self._mi4ip(True).getAttempt(),
			"ipjailfailures":	lambda self: self._mi4ip().getAttempt(),
			# raw ticket info:
			"raw-ticket":			lambda self: repr(self.__ticket),
			# jail info:
			"jail.name":         lambda self: self.__jail.name,
			"jail.banned":       lambda self: self.__jail.actions.banManager.size(),
			"jail.banned_total": lambda self: self.__jail.actions.banManager.getBanTotal(),
			"jail.found":        lambda self: self.__jail.filter.failManager.size(),
			"jail.found_total":  lambda self: self.__jail.filter.failManager.getFailTotal()
		}

		__slots__ = CallingMap.__slots__ + ('__ticket', '__jail', '__mi4ip')

		def __init__(self, ticket, jail=None, immutable=True, data=AI_DICT):
			self.__ticket = ticket
			self.__jail = jail
			self.storage = dict()
			self.immutable = immutable
			self.data = data
		
		def copy(self): # pragma: no cover
			return self.__class__(self.__ticket, self.__jail, self.immutable, self.data.copy())

		def _getBanTime(self):
			btime = self.__ticket.getBanTime()
			if btime is None: btime = self.__jail.actions.getBanTime()
			return int(btime)

		def _mi4ip(self, overalljails=False):
			"""Gets bans merged once, a helper for lambda(s), prevents stop of executing action by any exception inside.

			This function never returns None for ainfo lambdas - always a ticket (merged or single one)
			and prevents any errors through merging (to guarantee ban actions will be executed).
			[TODO] move merging to observer - here we could wait for merge and read already merged info from a database

			Parameters
			----------
			overalljails : bool
				switch to get a merged bans :
				False - (default) bans merged for current jail only
				True - bans merged for all jails of current ip address

			Returns
			-------
			BanTicket 
				merged or self ticket only
			"""
			if not hasattr(self, '__mi4ip'):
				self.__mi4ip = {}
			mi = self.__mi4ip
			idx = 'all' if overalljails else 'jail'
			if idx in mi:
				return mi[idx] if mi[idx] is not None else self.__ticket
			try:
				jail = self.__jail
				ip = self['ip']
				mi[idx] = None
				if not jail.database: # pragma: no cover
					return self.__ticket
				if overalljails:
					mi[idx] = jail.database.getBansMerged(ip=ip)
				else:
					mi[idx] = jail.database.getBansMerged(ip=ip, jail=jail)
			except Exception as e:
				logSys.error(
					"Failed to get %s bans merged, jail '%s': %s",
					idx, jail.name, e,
					exc_info=logSys.getEffectiveLevel()<=logging.DEBUG)
			return mi[idx] if mi[idx] is not None else self.__ticket


	def _getActionInfo(self, ticket):
		if not ticket:
			ticket = BanTicket("", MyTime.time())
		aInfo = Actions.ActionInfo(ticket, self._jail)
		return aInfo

	def _recordBanLatency(self, ticket, when=None):
		when = MyTime.time() if when is None else when
		started = ticket.getData('matched_at')
		if started is None:
			started = ticket.getTime()
		try:
			latency = max(0.0, float(when) - float(started))
		except (TypeError, ValueError):
			return
		metrics = self._ban_metrics
		metrics['latency_count'] += 1
		metrics['latency_total'] += latency
		metrics['latency_max'] = max(metrics['latency_max'], latency)

	def _recordActionSuccess(self, name, tickets, when=None):
		self._ban_by_action[name] = self._ban_by_action.get(name, 0) + len(tickets)
		for ticket in tickets:
			self._recordBanLatency(ticket, when)

	def _recordFailedBan(self, name, ticket, error):
		entry = {
			'time': MyTime.time(),
			'action': name,
			'ip': str(ticket.getID()),
			'error': str(error),
		}
		self._failed_bans.append(entry)
		if len(self._failed_bans) > 1000:
			del self._failed_bans[:-1000]
		logSys.error("[%s] Failed to ban %s using action %r: %s",
			self._jail.name, entry['ip'], name, error)
		self.audit('ban-failed', ip=entry['ip'], actor='fail2ban',
			reason=str(error), details={'action': name})

	def audit(self, action, ip=None, actor=None, source=None, reason=None,
			details=None):
		"""Write an immutable operational audit record."""
		actor = actor or 'fail2ban'
		reason = reason or ''
		logSys.notice("[%s] audit: action=%s ip=%s actor=%s source=%s reason=%s",
			self._jail.name, action, ip, actor, source or '', reason)
		db = self._jail.database
		if db is None:
			return
		observer = Observers.Main
		if observer is not None and observer.active and observer.paused is False:
			observer.add('audit', {
				'action': action, 'ip': ip, 'jail': self._jail.name,
				'actor': actor, 'source': source, 'reason': reason,
				'details': details,
			})
			return
		try:
			db.addAudit(action, ip=ip, jail=self._jail.name, actor=actor,
				source=source, reason=reason, details=details)
		except Exception as e:
			logSys.error("[%s] Failed to persist audit action=%s ip=%s: %s",
				self._jail.name, action, ip, e,
				exc_info=logSys.getEffectiveLevel()<=logging.DEBUG)

	def _executeBanActions(self, ticket, aInfo):
		ip = ticket.getID()
		for name, action in self._actions.items():
			try:
				if ticket.restored and getattr(action, 'norestored', False):
					continue
				if not aInfo.immutable:
					aInfo.reset()
				action.ban(aInfo)
				self._recordActionSuccess(name, (ticket,))
			except Exception as e:
				logSys.error(
					"Failed to execute ban jail '%s' action '%s' "
					"info '%r': %s",
					self._jail.name, name, aInfo, e,
					exc_info=logSys.getEffectiveLevel()<=logging.DEBUG)
				self._recordFailedBan(name, ticket, e)
		logSys.debug("[%s] action ban completed for %s", self._jail.name, ip)

	def rebuildAction(self, action, name=None):
		"""Rebuild an action from the complete in-memory ban list.

		This is used after invariant repair, when an atomic chain was
		damaged or partially removed.  The action must rebuild in one
		operation when it supports bulk bans.
		"""
		if name is None:
			name = next((n for n, a in self._actions.items() if a is action), None)
		marker = name or id(action)
		if marker in self._rebuilding_actions:
			return False
		self._rebuilding_actions.add(marker)
		try:
			tickets = list(self.banManager)
			infos = [self._getActionInfo(ticket) for ticket in tickets]
			if getattr(action, '_has_batch_ban', False):
				infos = self._batchActionInfos(action, infos)
				action._banMany(infos)
			else:
				for ticket, aInfo in zip(tickets, infos):
					action.reban(aInfo)
			self._recordActionSuccess(name or '<action>', tickets)
			self.audit('chain-rebuild', actor='fail2ban',
				reason='invariant repair',
				details={'action': name, 'entries': len(tickets)})
			logSys.warning("[%s] action %r rebuilt with %d ban(s)",
				self._jail.name, name, len(tickets))
			return True
		except Exception as e:
			self._failed_bans.append({
				'time': MyTime.time(), 'action': name or '<action>',
				'ip': '*', 'error': str(e),
			})
			self.audit('chain-rebuild-failed', actor='fail2ban',
				reason=str(e), details={'action': name})
			logSys.error("[%s] failed to rebuild action %r: %s",
				self._jail.name, name, e)
			return False
		finally:
			self._rebuilding_actions.discard(marker)

	def flushBanBatch(self):
		"""Dispatch all queued bans as one atomic operation per action.

		Batch-capable actions receive one ``banMany`` call.  If it fails,
		the queue is replayed ticket by ticket (using ``fallback``) and
		every failed entry is retained for diagnostics.
		"""
		with self._ban_lock:
			items = self._batch_tickets
			self._batch_tickets = []
			self._batch_deadline = None
		if not items:
			return 0
		batch_capable = any(getattr(action, '_has_batch_ban', False)
			for action in self._actions.values())
		if batch_capable:
			self._ban_metrics['batch_dispatches'] += 1
			self._ban_metrics['batch_entries'] += len(items)
		for name, action in self._actions.items():
			applicable = [(ticket, aInfo) for ticket, aInfo in items
				if not (ticket.restored and getattr(action, 'norestored', False))]
			if not applicable:
				continue
			tickets = [ticket for ticket, aInfo in applicable]
			if getattr(action, '_has_batch_ban', False):
				# An atomic replacement contains the complete current ban
				# set, not only the newly collected batch.
				infos = [self._getActionInfo(ticket)
					for ticket in list(self.banManager)]
				infos = self._batchActionInfos(action, infos)
				try:
					action._banMany(infos)
					self._recordActionSuccess(name, tickets)
					continue
				except Exception as e:
					self._ban_metrics['batch_failures'] += 1
					for ticket in tickets:
						self._failed_batch_entries.append({
							'time': MyTime.time(),
							'action': name,
							'ip': str(ticket.getID()),
							'error': str(e),
						})
					if len(self._failed_batch_entries) > 10000:
						del self._failed_batch_entries[:-10000]
					logSys.error(
						"Failed to execute batch ban jail '%s' action '%s' "
						"for %d entries: %s",
						self._jail.name, name, len(applicable), e,
						exc_info=logSys.getEffectiveLevel()<=logging.DEBUG)
					self.audit('batch-failed', actor='fail2ban',
						reason=str(e),
						details={'action': name,
							'count': len(applicable),
							'ips': [str(ticket.getID())
								for ticket in tickets[:50]]})
					if not self._batch_fallback:
						for ticket in tickets:
							self._recordFailedBan(name, ticket, e)
						continue
				# Non-atomic or failed bulk action: replay each entry.
				self._ban_metrics['fallback_entries'] += len(applicable)
				for ticket, aInfo in applicable:
					try:
						if not aInfo.immutable:
							aInfo.reset()
						action.ban(aInfo)
						self._recordActionSuccess(name, (ticket,))
					except Exception as e:
						self._recordFailedBan(name, ticket, e)
			else:
				for ticket, aInfo in applicable:
					try:
						if not aInfo.immutable:
							aInfo.reset()
						action.ban(aInfo)
						self._recordActionSuccess(name, (ticket,))
					except Exception as e:
						self._recordFailedBan(name, ticket, e)
		return len(items)

	def __getFailTickets(self, count=100):
		"""Generator to get maximal count failure tickets from fail-manager."""
		cnt = 0
		while cnt < count:
			ticket = self._jail.getFailTicket()
			if not ticket:
				break
			yield ticket
			cnt += 1

	def __checkBan(self, tickets=None):
		with self._ban_lock:
			return self.__checkBanLocked(tickets)

	def __checkBanLocked(self, tickets=None):
		"""Check for IP address to ban.

		If tickets are not specified look in the jail queue for FailTicket. If a ticket is available,
		it executes the "ban" command and adds a ticket to the BanManager.

		Returns
		-------
		bool
			True if an IP address get banned.
		"""
		cnt = 0
		if not tickets:
			tickets = self.__getFailTickets(self.banPrecedence)
		rebanacts = None
		for ticket in tickets:

			bTicket = BanTicket.wrap(ticket)
			btime = ticket.getBanTime(self.banManager.getBanTime())
			ip = bTicket.getID()
			# A whitelist entry can be added while a ticket is still queued;
			# enforce it again immediately before touching the firewall.
			if self._jail.filter is not None and \
					self._jail.filter.inExplicitWhitelist(ip):
				self.audit('ban-skipped-whitelist', ip=ip,
					actor=bTicket.getData('actor', 'fail2ban-filter'),
					reason='whitelisted')
				continue
			aInfo = self._getActionInfo(bTicket)
			reason = {}
			if self.banManager.addBanTicket(bTicket, reason=reason):
				cnt += 1
				# report ticket to observer, to check time should be increased and hereafter observer writes ban to database (asynchronous)
				if Observers.Main is not None and not bTicket.restored:
					Observers.Main.add('banFound', bTicket, self._jail, btime)
				logSys.notice("[%s] %sBan %s", self._jail.name, ('' if not bTicket.restored else 'Restore '), ip)
				self.audit('restore-ban' if bTicket.restored else 'ban', ip=ip,
					actor=bTicket.getData('actor', 'fail2ban-filter'),
					source=bTicket.getData('source'),
					reason=bTicket.getData('ban_reason', 'log match'),
					details={'action': 'restore' if bTicket.restored else 'filter'})
				if self._batch_enabled:
					with self._ban_lock:
						self._batch_tickets.append((bTicket, aInfo))
						if self._batch_deadline is None:
							self._batch_deadline = time.time() + self._batch_timeout
						if len(self._batch_tickets) >= self._batch_size:
							self.flushBanBatch()
				else:
					self._executeBanActions(bTicket, aInfo)
				# after all actions are processed set banned flag:
				bTicket.banned = True
				if self.banEpoch: # be sure tickets always have the same ban epoch (default 0):
					bTicket.banEpoch = self.banEpoch
			else:
				if reason.get('expired', 0):
					logSys.info('[%s] Ignore %s, expired bantime', self._jail.name, ip)
					continue
				bTicket = reason.get('ticket', bTicket)
				# if already banned (otherwise still process some action)
				if bTicket.banned:
					# compare time of failure occurrence with time ticket was really banned:
					diftm = ticket.getTime() - bTicket.getTime()
					# log already banned with following level:
					#   DEBUG   - before 3 seconds - certain interval for it, because of possible latency by recognizing in backends, etc.
					#   NOTICE  - before 60 seconds - may still occur if action is slow, or very high load in backend,
					#   WARNING - after 60 seconds - very long time, something may be wrong
					ll = logging.DEBUG   if diftm < 3 \
					else logging.NOTICE  if diftm < 60 \
					else logging.WARNING
					logSys.log(ll, "[%s] %s already banned", self._jail.name, ip)
					# if long time after ban - do consistency check (something is wrong here):
					if bTicket.banEpoch == self.banEpoch and diftm > 3:
						# avoid too often checks:
						if not rebanacts and MyTime.time() > self.__lastConsistencyCheckTM + 3:
							self.__lastConsistencyCheckTM = MyTime.time()
							for action in self._actions.values():
								if hasattr(action, 'consistencyCheck'):
									action.consistencyCheck()
					# check epoch in order to reban it:
					if bTicket.banEpoch < self.banEpoch:
						if not rebanacts: rebanacts = dict(
							(name, action) for name, action in self._actions.items()
								if action.banEpoch > bTicket.banEpoch)
						cnt += self.__reBan(bTicket, actions=rebanacts)
				else: # pragma: no cover - unexpected: ticket is not banned for some reasons - reban using all actions:
					cnt += self.__reBan(bTicket)
			# add ban to database moved to observer (should previously check not already banned 
			# and increase ticket time if "bantime.increment" set)
		if cnt:
			logSys.debug("Banned %s / %s, %s ticket(s) in %r", cnt, 
				self.banManager.getBanTotal(), self.banManager.size(), self._jail.name)
		return cnt

	def __reBan(self, ticket, actions=None, log=True):
		"""Repeat bans for the ticket.

		Executes the actions in order to reban the host given in the
		ticket.

		Parameters
		----------
		ticket : Ticket
			Ticket to reban
		"""
		actions = actions or self._actions
		ip = ticket.getID()
		aInfo = self._getActionInfo(ticket)
		if log:
			logSys.notice("[%s] Reban %s%s", self._jail.name, ip, (', action %r' % list(actions.keys())[0] if len(actions) == 1 else ''))
		for name, action in actions.items():
			try:
				logSys.debug("[%s] action %r: reban %s", self._jail.name, name, ip)
				if not aInfo.immutable: aInfo.reset()
				action.reban(aInfo)
			except Exception as e:
				logSys.error(
					"Failed to execute reban jail '%s' action '%s' "
					"info '%r': %s",
					self._jail.name, name, aInfo, e,
					exc_info=logSys.getEffectiveLevel()<=logging.DEBUG)
				return 0
		# after all actions are processed set banned flag:
		ticket.banned = True
		if self.banEpoch: # be sure tickets always have the same ban epoch (default 0):
			ticket.banEpoch = self.banEpoch
		return 1

	def _prolongBan(self, ticket):
		# prevent to prolong ticket that was removed in-between,
		# if it in ban list - ban time already prolonged (and it stays there):
		if not self.banManager._inBanList(ticket): return
		# do actions :
		aInfo = None
		for name, action in self._actions.items():
			try:
				if ticket.restored and getattr(action, 'norestored', False):
					continue
				if not action._prolongable:
					continue
				if aInfo is None:
					aInfo = self._getActionInfo(ticket)
				if not aInfo.immutable: aInfo.reset()
				action.prolong(aInfo)
			except Exception as e:
				logSys.error(
					"Failed to execute ban jail '%s' action '%s' "
					"info '%r': %s",
					self._jail.name, name, aInfo, e,
					exc_info=logSys.getEffectiveLevel()<=logging.DEBUG)

	def __checkUnBan(self, maxCount=None):
		"""Check for IP address to unban.

		Unban IP addresses which are outdated.
		"""
		lst = self.banManager.unBanList(MyTime.time(), maxCount)
		for ticket in lst:
			self.__unBan(ticket)
			self.audit('unban-expired', ip=ticket.getID(), actor='fail2ban',
				reason='ban time expired')
		cnt = len(lst)
		if cnt:
			logSys.debug("Unbanned %s, %s ticket(s) in %r", 
				cnt, self.banManager.size(), self._jail.name)
		return cnt

	def __flushBan(self, db=False, actions=None, stop=False):
		"""Flush the ban list.

		Unban all IP address which are still in the banning list.

		If actions specified, don't flush list - just execute unban for 
		given actions (reload, obsolete resp. removed actions).
		"""
		log = "Unban" if not stop else "Repeal Ban"
		if actions is None:
			logSys.debug("  Flush ban list")
			lst = self.banManager.flushBanList()
		else:
			log = None # don't log "[jail] Unban ..." if removing actions only.
			lst = iter(self.banManager)
		cnt = 0
		# first we'll execute flush for actions supporting this operation:
		unbactions = {}
		for name, action in (actions if actions is not None else self._actions).items():
			try:
				if hasattr(action, 'flush') and (not isinstance(action, CommandAction) or action.actionflush):
					logSys.notice("[%s] Flush ticket(s) with %s", self._jail.name, name)
					if action.flush():
						continue
			except Exception as e:
				logSys.error("Failed to flush bans in jail '%s' action '%s': %s",
					self._jail.name, name, e,
					exc_info=logSys.getEffectiveLevel()<=logging.DEBUG)
				logSys.info("No flush occurred, do consistency check")
				if hasattr(action, 'consistencyCheck'):
					def _beforeRepair():
						if stop and not getattr(action, 'actionrepair_on_unban', None): # don't need repair on stop
							logSys.error("Invariant check failed. Flush is impossible.")
							return False
						return True
					action.consistencyCheck(_beforeRepair)
					continue
			# fallback to single unbans:
			logSys.debug("  Unban tickets each individually")
			unbactions[name] = action
		actions = unbactions
		# flush the database also:
		if db and self._jail.database is not None:
			logSys.debug("  Flush jail in database")
			self._jail.database.delBan(self._jail)
		# unban each ticket with non-flusheable actions:
		for ticket in lst:
			# unban ip:
			self.__unBan(ticket, actions=actions, log=log)
			self.audit('unban-all' if not stop else 'unban-shutdown',
				ip=ticket.getID(), actor='fail2ban',
				reason='flush')
			cnt += 1
		logSys.debug("  Unbanned %s, %s ticket(s) in %r", 
			cnt, self.banManager.size(), self._jail.name)
		return cnt

	def __unBan(self, ticket, actions=None, log="Unban"):
		"""Unbans host corresponding to the ticket.

		Executes the actions in order to unban the host given in the
		ticket.

		Parameters
		----------
		ticket : FailTicket
			Ticket of failures of which to unban
		"""
		if actions is None:
			unbactions = self._actions
		else:
			unbactions = actions
		ip = ticket.getID()
		aInfo = self._getActionInfo(ticket)
		self._ban_metrics['unbanned'] += 1
		if log:
			logSys.notice("[%s] %s %s", self._jail.name, log, ip)
		for name, action in unbactions.items():
			try:
				logSys.debug("[%s] action %r: unban %s", self._jail.name, name, ip)
				if not aInfo.immutable: aInfo.reset()
				action.unban(aInfo)
			except Exception as e:
				logSys.error(
					"Failed to execute unban jail '%s' action '%s' "
					"info '%r': %s",
					self._jail.name, name, aInfo, e,
				exc_info=logSys.getEffectiveLevel()<=logging.DEBUG)

	def getBanStatistics(self):
		metrics = self._ban_metrics
		avg = (metrics['latency_total'] / metrics['latency_count']
			if metrics['latency_count'] else 0.0)
		return {
			'current': self.banManager.size(),
			'total': self.banManager.getBanTotal(),
			'unbanned': metrics['unbanned'],
			'by_action': dict(self._ban_by_action),
			'batch': {
				'enabled': self._batch_enabled,
				'pending': len(self._batch_tickets),
				'dispatches': metrics['batch_dispatches'],
				'entries': metrics['batch_entries'],
				'failures': metrics['batch_failures'],
				'fallback_entries': metrics['fallback_entries'],
				'failed_entry_count': len(self._failed_batch_entries),
				'failed_entries': list(self._failed_batch_entries[-100:]),
			},
			'latency': {
				'count': metrics['latency_count'],
				'average_ms': round(avg * 1000.0, 3),
				'max_ms': round(metrics['latency_max'] * 1000.0, 3),
			},
			'failed': list(self._failed_bans),
			'chain_max': self._chain_max,
			'chain_overflow': self._chain_overflow,
			'chain_aggregated': self._chain_aggregated,
			'whitelist': self._jail.filter.getIgnoreIPStats()
				if self._jail.filter is not None else {},
		}

	def status(self, flavor="basic"):
		"""Status of current and total ban counts and current banned IP list.
		"""
		# TODO: Allow this list to be printed as 'status' output
		supported_flavors = ["short", "basic", "stats", "cymru", "banstats"]
		if flavor is None or flavor not in supported_flavors:
			logSys.warning("Unsupported extended jail status flavor %r. Supported: %s" % (flavor, supported_flavors))
		if flavor == "stats":
			return (self.banManager.size(), self.banManager.getBanTotal())
		if flavor == "banstats":
			stats = self.getBanStatistics()
			return [
				("Currently banned", stats['current']),
				("Total banned", stats['total']),
				("Total unbanned", stats['unbanned']),
				("Bans by action", stats['by_action']),
				("Batch dispatch", stats['batch']),
				("Match to rule latency", stats['latency']),
				("Failed ban entries", len(stats['failed'])),
				("Failed batch entries", stats['batch']['failed_entry_count']),
				("Whitelist entries", stats['whitelist']),
				("Chain max", stats['chain_max']),
			]
		# Always print this information (basic)
		if flavor != "short":
			banned = self.banManager.getBanList()
			cnt = len(banned)
		else:
			cnt = self.banManager.size()
		ret = [("Currently banned", cnt),
			   ("Total banned", self.banManager.getBanTotal())]
		if flavor != "short":
			ret += [("Banned IP list", banned)]
		if flavor == "cymru":
			cymru_info = self.banManager.getBanListExtendedCymruInfo()
			ret += \
				[("Banned ASN list", self.banManager.geBanListExtendedASN(cymru_info)),
				 ("Banned Country list", self.banManager.geBanListExtendedCountry(cymru_info)),
				 ("Banned RIR list", self.banManager.geBanListExtendedRIR(cymru_info))]
		return ret
