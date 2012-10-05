#!/usr/bin/python

import os
import time

from k5test import *


iprop_kdc_conf = {
    'all' : { 'libdefaults' : { 'default_realm' : 'KRBTEST.COM'},
              'realms' : { '$realm' : {
                'iprop_enable' : 'true',
                'iprop_slave_poll' : '1'
                }}},
    'master' : { 'realms' : { '$realm' : {
                'iprop_logfile' : '$testdir/db.ulog'
                }}},
    'slave' : { 'realms' : { '$realm' : {
                'iprop_logfile' : '$testdir/slave-db.ulog'
                }}}
}

realm = K5Realm(kdc_conf=iprop_kdc_conf, create_user=False, start_kadmind=True)

ulog = os.path.join(realm.testdir, 'db.ulog')
if not os.path.exists(ulog):
    fail('update log not created: ' + ulog)

# Create the principal used to authenticate kpropd to kadmind.
kiprop_princ = 'kiprop/' + hostname
realm.addprinc(kiprop_princ)
realm.extract_keytab(kiprop_princ, realm.keytab)

# Create the slave db.
dumpfile = os.path.join(realm.testdir, 'dump')
realm.run_as_master([kdb5_util, 'dump', dumpfile])
realm.run_as_slave([kdb5_util, 'load', dumpfile])
realm.run_as_slave([kdb5_util, 'stash', '-P', 'master'])

# Create a pipe over which kpropd will update us.
#
# kpropd will block if we don't open this pipe for reading, but we'll
# block if kpropd doesn't open it for writing.  This hack gets us past
# this deadlock by forking off a dd(1) process to read 1 char from this
# pipe (which kpropd will dutifully write).
testpipe = os.path.join(realm.testdir, 'fifo')
realm.run_as_slave(['mknod', testpipe, 'p'])
realm.run_as_slave(['sh', '-c',
                    'exec </dev/null > /dev/null 2>&1; '
                    '(dd if=' + testpipe + ' of=/dev/null bs=1 count=1 &); exit 0'])

# This function will wait for updates from the kpropd.
#
# kpropd writes 'i' for incrementals received, 'r' for full resync succeeded,
# 'e' for error, and 'o' for any result from iprop_get_updates_1() other than
# UPDATE_NIL or UPDATE_FULL_RESYNC_NEEDED.
#
# Note that sometimes when we expect a full resync we still need to
# wait for an 'i' because the full resync may be of an older dump and
# then kpropd will get incrementals.
def waitforit(p, it):
    output('Waiting for: ' + it + '\n')
    c = p.read(1)
    output('Got: ' + c + '\n')
    while c != it:
        c = p.read(1)
        output('Got: ' + c + '\n')
        if c == 'e':
            fail('kpropd had an error.')
    output('Got it\n')

# Make some changes to the master db.
realm.addprinc('wakawaka')
# Add a principal enough to make realloc likely, but not enough to grow
# basic ulog entry size.
c = 'chocolate-flavored-school-bus'
cs = c + '/'
longname = cs + cs + cs + cs + cs + cs + cs + cs + cs + cs + cs + cs + c
realm.addprinc(longname)
realm.addprinc('w')
realm.run_kadminl('modprinc -allow_tix w')
realm.run_kadminl('modprinc +allow_tix w')

out = realm.run_as_master([kproplog, '-h'])
if 'Last serial # : 7' not in out:
    fail('Update log on master has incorrect last serial number.')

# Set up the kpropd acl file.
acl_file = os.path.join(realm.testdir, 'kpropd-acl')
acl = open(acl_file, 'w')
acl.write(realm.host_princ + '\n')
acl.close()

realm.start_kpropd()
output('Opening FIFO to read status notices from kpropd.\n')
fifo = open(testpipe, 'r')
realm.run_kadminl('modprinc -allow_tix w')
out = realm.run_as_master([kproplog, '-h'])
if 'Last serial # : 8' not in out:
    fail('Update log on master has incorrect last serial number.')

# We need to give iprop (really, a full resync here and maybe an
# incremental) a chance to happen.
#
# Sometimes we need to wait a long time because kpropd's do_iprop()
# can race with kadmind and fail to kadm5 init, which leads -apparently-
# to some backoff effect.
waitforit(fifo, 'r')

# Now check that iprop happened.
out = realm.run_as_slave([kproplog, '-h'])
if 'Last serial # : 8' not in out:
    fail('Update log on slave has incorrect last serial number.')

# Make another change.
realm.run_kadminl('modprinc +allow_tix w')
out = realm.run_as_master([kproplog, '-h'])
if 'Last serial # : 9' not in out:
    fail('Update log on master has incorrect last serial number.')

# Check that we're at sno 9 on the slave side too.
waitforit(fifo, 'i')
out = realm.run_as_slave([kproplog, '-h'])
if 'Last serial # : 9' not in out:
    fail('Update log on slave has incorrect last serial number.')

# Reset the ulog on the slave side to force a full resync to the slave.
realm.run_as_slave([kproplog, '-R'])
out = realm.run_as_slave([kproplog, '-h'])
if 'Last serial # : None' not in out:
    fail('Reset of update log on slave failed.')
waitforit(fifo, 'r')
waitforit(fifo, 'i')
# Check that a full resync happened.
out = realm.run_as_slave([kproplog, '-h'])
if 'Last serial # : 9' not in out:
    fail('Update log on slave has incorrect last serial number.')

# Make another change.
realm.run_kadminl('modprinc +allow_tix w')
out = realm.run_as_master([kproplog, '-h'])
if 'Last serial # : 10' not in out:
    fail('Update log on master has incorrect last serial number.')

waitforit(fifo, 'i')
out = realm.run_as_slave([kproplog, '-h'])
if 'Last serial # : 10' not in out:
    fail('Update log on slave has incorrect last serial number.')

# Reset the ulog on the master side to force a full resync to all slaves.
#
# XXX Note that we only have one slave in this test, so we can't really
# test this.  Also, there can only be one port for the kpropd on the
# slave side so we can't test multiple slaves unless we add a new iprop
# RPC by which the slave can request a kprop to a specific port.
realm.run_as_master([kproplog, '-R'])
out = realm.run_as_master([kproplog, '-h'])
if 'Last serial # : None' not in out:
    fail('Reset of update log on master failed.')
realm.run_kadminl('modprinc -allow_tix w')
out = realm.run_as_master([kproplog, '-h'])
if 'Last serial # : 1' not in out:
    fail('Update log on master has incorrect last serial number.')
waitforit(fifo, 'r')
# Check that a full resync happened.
out = realm.run_as_slave([kproplog, '-h'])
if 'Last serial # : 1' not in out:
    fail('Update log on slave has incorrect last serial number.')

success('iprop tests.')
