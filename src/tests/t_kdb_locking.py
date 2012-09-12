#!/usr/bin/python

# This is a regression test for
# https://bugzilla.redhat.com/show_bug.cgi?id=586032 .
#
# We start a KDC, remove the kadm5 lock file, use the KDC, re-create the
# kadm5 lock file, and use kadmin.local.  The kinit should fail, and the
# kadmin.local should succeed.


import os

from k5test import *

kdc_conf = {
    'all' : { 'libdefaults' : { 'default_realm' : 'KRBTEST.COM'}}
}

p = 'foo'
realm = K5Realm(kdc_conf=kdc_conf, create_user=False)
realm.addprinc(p, p)

kdc_log = os.path.join(realm.testdir, 'kdc.log')
kadm5_lock = os.path.join(realm.testdir, 'master-db.kadm5.lock')
if not os.path.exists(kadm5_lock):
    fail('kadm5 lock file not created: ' + kadm5_lock)
os.unlink(kadm5_lock)

try:
    realm.kinit(p, p)
except:
    1

f = open(kdc_log, 'r')
if 'A service is not available' not in f.read():
    fail('krb5kdc should have returned service not available error')

try:
    f = open(kadm5_lock, 'w')
except:
    fail('could not re-create kadm5 lock file')
f.close()

output = realm.run_kadminl('modprinc -allow_tix ' + p)
if 'Cannot lock database' in output:
    fail('krb5kdc still holds a lock on the principal db')

success('kdb_locking tests.')
