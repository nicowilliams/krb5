#!/usr/bin/python

# XXX comment here
kprop_port = '61010'
import os
os.environ['KPROP_PORT'] = kprop_port

from k5test import *

iprop_kdc_conf = {
    'all' : { 'libdefaults' : { 'default_realm' : 'KRBTEST.COM'},
              'realms' : { '$realm' : {
                'iprop_enable' : 'true',
                'iprop_port' : '$port4'
                }}},
    'master' : { 'realms' : { '$realm' : {
                'iprop_logfile' : '$testdir/db.ulog'
                }}},
    'slave' : { 'realms' : { '$realm' : {
                'iprop_logfile' : '$testdir/slave-db.ulog',
                'iprop_poll' : '5'
                }}}
}

realm = K5Realm(kdc_conf=iprop_kdc_conf, create_user=False)

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
#realm.start_kadmind()
realm.run_as_master(['/bin/bash', '-c', ' '.join([kadmind, '-nofork',
                    '>>' + os.path.join(realm.testdir, 'kadmind5.log'), '2>&1', '&' ])])
realm.run_as_slave(['/bin/sleep', '2'])

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

output = realm.run_as_master([kproplog])
# XXX examine kproplog output

# Set up the kpropd acl file.
acl_file = os.path.join(realm.testdir, 'kpropd-acl')
acl = open(acl_file, 'w')
acl.write(realm.host_princ + '\n')
acl.close()

# XXX need to start this as a daemon; need k5test support, sentinel
incoming = os.path.join(realm.testdir, 'incoming-slave-datatrans')
realm.run_as_slave(['/bin/bash', '-c', ' '.join([kpropd, '-d', '-D', '-P', kprop_port, '-f', incoming,
                    '-p', kdb5_util, '-a', acl_file, '>' + os.path.join(realm.testdir, 'kpropd-slave.log'), '2>&1', '&' ])])
#realm.start_kpropd()
realm.run_kadminl('modprinc -allow_tix w')
realm.run_as_slave(['/bin/sleep', '1005'])
output = realm.run_as_slave([kproplog])

success('iprop tests.')
