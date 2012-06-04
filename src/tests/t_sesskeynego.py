#!/usr/bin/python
from k5test import *

krb5_conf1 = {
    'all' : {
        'libdefaults' : {
            'default_tkt_enctypes' : 'aes128-cts,aes256-cts'
        }
    }
}

krb5_conf2 = {
    'all' : {
        'libdefaults' : {
            'default_tkt_enctypes' : 'aes256-cts,aes128-cts'
        }
    }
}

krb5_conf3 = {
    'all' : {
        'libdefaults' : {
            'allow_weak_crypto' : 'true',
            'default_tkt_enctypes' : 'rc4-hmac,aes128-cts,des-cbc-crc'
        }
    }
}

krb5_conf4 = {
    'all' : {
        'libdefaults' : {
            'allow_weak_crypto' : 'true',
            'default_tkt_enctypes' : 'des-cbc-crc,rc4-hmac,aes128-cts'
        },
        'realms' : {
            '$realm' : {
                'des_crc_session_supported' : 'false'
            }
        }
    }
}

# First go
realm = K5Realm(krb5_conf=krb5_conf1)

realm.run_kadminl('cpw -randkey -e aes256-cts-hmac-sha1-96:normal %s ' %
                  (realm.host_princ,))
realm.run_kadminl('setstr %s session_enctypes aes128-cts,aes256-cts' %
                  (realm.host_princ,))

realm.kinit(realm.user_princ, password('user'))
realm.run_as_client([kvno, realm.host_princ])
output = realm.run_as_client([klist, '-e'])

expected = '%s\n\tEtype (skey, tkt): ' \
    'aes128-cts-hmac-sha1-96, aes256-cts-hmac-sha1-96' % \
    (realm.host_princ,)

if expected not in output:
    fail('sesskeynego: expected TGS enctype not found after change')

realm.stop()

# Second go, almost same as first, but resulting session key must be aes256
# because of the difference in default_tkt_enctypes order.  This tests that
# session_enctypes feature doesn't change the order in which we negotiate.
realm = K5Realm(krb5_conf=krb5_conf2)

realm.run_kadminl('cpw -randkey -e aes256-cts-hmac-sha1-96:normal %s ' %
                  (realm.host_princ,))
realm.run_kadminl('setstr %s session_enctypes aes128-cts,aes256-cts' %
                  (realm.host_princ,))

realm.kinit(realm.user_princ, password('user'))
realm.run_as_client([kvno, realm.host_princ])
output = realm.run_as_client([klist, '-e'])

expected = '%s\n\tEtype (skey, tkt): ' \
    'aes256-cts-hmac-sha1-96, aes256-cts-hmac-sha1-96' % \
    (realm.host_princ,)

if expected not in output:
    fail('sesskeynego: expected TGS enctype not found after change')

realm.stop()

# Next we use krb5_conf3 and try various things
realm = K5Realm(krb5_conf=krb5_conf3)

realm.run_kadminl('cpw -randkey -e aes256-cts-hmac-sha1-96:normal %s ' % (realm.host_princ,))

# 3a
realm.run_kadminl('setstr %s session_enctypes aes128-cts,aes256-cts' %
                  (realm.host_princ,))

realm.kinit(realm.user_princ, password('user'))
realm.run_as_client([kvno, realm.host_princ])
output = realm.run_as_client([klist, '-e'])

expected = '%s\n\tEtype (skey, tkt): ' \
    'aes128-cts-hmac-sha1-96, aes256-cts-hmac-sha1-96' % \
    (realm.host_princ,)

if expected not in output:
    fail('sesskeynego: expected TGS enctype not found after change')

# 3b
realm.run_kadminl('setstr %s session_enctypes rc4-hmac,aes128-cts,aes256-cts' %
                  (realm.host_princ,))

realm.kinit(realm.user_princ, password('user'))
realm.run_as_client([kvno, realm.host_princ])
output = realm.run_as_client([klist, '-e'])

expected = '%s\n\tEtype (skey, tkt): ' \
    'arcfour-hmac, aes256-cts-hmac-sha1-96' % \
    (realm.host_princ,)

if expected not in output:
    fail('sesskeynego: expected TGS enctype not found after change')

# 3c Test des-cbc-crc default assumption
realm.run_kadminl('setstr %s session_enctypes unknown' %
                  (realm.host_princ,))

realm.kinit(realm.user_princ, password('user'))
realm.run_as_client([kvno, realm.host_princ])
output = realm.run_as_client([klist, '-e'])

expected = '%s\n\tEtype (skey, tkt): ' \
    'des-cbc-crc, aes256-cts-hmac-sha1-96' % \
    (realm.host_princ,)

if expected not in output:
    fail('sesskeynego: expected TGS enctype not found after change')

realm.stop()

# Last go: test that we can disable the des-cbc-crc assumption
realm = K5Realm(krb5_conf=krb5_conf4)

realm.run_kadminl('cpw -randkey -e aes256-cts-hmac-sha1-96:normal %s ' %
                  (realm.host_princ,))

realm.kinit(realm.user_princ, password('user'))
realm.run_as_client([kvno, realm.host_princ])
output = realm.run_as_client([klist, '-e'])

expected = '%s\n\tEtype (skey, tkt): ' \
    'aes256-cts-hmac-sha1-96, aes256-cts-hmac-sha1-96' % \
    (realm.host_princ,)

if expected not in output:
    fail('sesskeynego: expected TGS enctype not found after change')

realm.stop()

success('sesskeynego')
