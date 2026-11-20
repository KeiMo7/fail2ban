Batched and atomic bans
=======================

Batching is opt-in.  The historical one-ticket-at-a-time action path stays
the default.

Configuration
-------------

Use the atomic iptables action and enable batching in the jail::

    [sshd]
    banaction = iptables-batch
    banbatch = true
    banbatchsize = 2000
    banbatchtimeout = 2
    banbatchfallback = true
    banchainmax = 20000
    banchainoverflow = aggregate

``iptables-batch`` keeps a stable dispatcher chain and two generation chains.
Each batch is written into the inactive generation with one
``iptables-restore --noflush`` transaction per ``batchchunksize`` entries
(500 by default, below the kernel netlink message limit).  Only after every
chunk succeeds does a single ``iptables -R`` atomically point the dispatcher
at the new generation.
A failed build leaves the previous generation active.  A single unban uses
``iptables -D`` and does not rebuild the chain unless exact CIDR compaction is
active due to ``banchainmax``.

If a batch command fails, the same ticket set is replayed through
``actionban``.  Failed entries are recorded in the audit log and exposed by
``status``.

Whitelisting a false positive
-----------------------------

The following one-shot command removes the address from every jail and adds it
to the operational whitelist.  It is persisted before the firewall update::

    fail2ban-client whitelistip --source ops --reason "shared egress" 203.0.113.4

Sources are independent, for example ``ops``, ``monitor`` and ``partner``::

    fail2ban-client whitelistip --source partner 198.51.100.0/24
    fail2ban-client get sshd whitelist
    fail2ban-client get sshd whiteliststats
    fail2ban-client set sshd delwhitelistip --source partner 198.51.100.0/24

The regular log parsing and jail decision path is unchanged.  Whitelist
entries are checked both before a failure is counted and immediately before a
queued ticket reaches a firewall action.

Operations and persistence
--------------------------

Ban, unban, whitelist, bulk-failure, expiry and chain-rebuild events are
written to the existing SQLite database.  Records include time, actor, source,
jail, IP and reason::

    fail2ban-client audit --ip 203.0.113.4
    fail2ban-client audit --action ban --since 1760000000

Whitelist provenance is also stored.  On restart fail2ban restores the
whitelist before current bans, and the existing validity checks discard
expired tickets.

Metrics
-------

``banstats`` reports current/total/unbanned counts, bans grouped by action,
batch dispatch/failure counters, match-to-rule latency and failed entries::

    fail2ban-client status sshd banstats
    fail2ban-client banstats

``banchainmax`` prevents unbounded chain growth.  ``aggregate`` computes an
exact CIDR cover (without widening the blocked address set).  If the compacted
set still exceeds the limit, fail2ban logs an error recommending an
ipset/nftables action.

Benchmark
---------

Run the dependency-free control-plane benchmark with::

    python3 -m fail2ban.tests.batchbenchmark

It drives 20,000 bans through both paths, probes the active chain while a full
replacement is being built, injects a failed build, and verifies single-entry
unban state.  It does not require root and does not alter the host firewall.

For a real-kernel iptables run, use an isolated user/network namespace::

    unshare -Urn python3 -m fail2ban.tests.iptables_batchbenchmark

This performs packet-level loopback probes against the active generation,
verifies that a failed ``iptables-restore`` leaves the dispatcher unchanged,
and checks that a single unban removes exactly one rule.
