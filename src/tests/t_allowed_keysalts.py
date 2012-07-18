#!/usr/bin/python
from k5test import *
import re

# Run "kvno server" with a fresh set of client tickets, then check that the
# enctypes in the service ticket match the expected values.
re = re.compile(r'Unsupported encryption type while randomizing key')

krb5_conf1 = {'all': {'libdefaults': {
            'supported_enctypes': 'aes256-cts'}}}

realm = K5Realm(krb5_conf=krb5_conf1, create_host=False, get_creds=False)

# Add policies
realm.run_kadminl('addpol -allowedkeysalts aes256-cts:normal ak1')
realm.run_kadminl('addpol -allowedkeysalts aes256-cts:normal,rc4-hmac:normal ak2')

realm.run_kadminl('addprinc -randkey -e aes256-cts:normal server')

# Test with one-enctype allowed_keysalts
realm.run_kadminl('modprinc -policy ak1 server')
realm.run_kadminl('getprinc server')
output = realm.run_kadminl('cpw -randkey -e aes128-cts:normal server')
if not re.search(output):
    fail('allowed_keysalts policy not applied properly')
realm.run_kadminl('getprinc server')
output = realm.run_kadminl('cpw -randkey -e aes256-cts:normal server')
if re.search(output):
    fail('allowed_keysalts policy not applied properly')
realm.run_kadminl('getprinc server')

# Now test a multi-enctype allowed_keysalts.  Test that subsets are allowed,
# the the complete set is allowed, that order doesn't matter, and that
# enctypes outside the set are not allowed.
realm.run_kadminl('modprinc -policy ak2 server')
output = realm.run_kadminl('cpw -randkey -e rc4-hmac:normal server')
if re.search(output):
    fail('allowed_keysalts policy not applied properly')
realm.run_kadminl('getprinc server')
output = realm.run_kadminl('cpw -randkey -e aes256-cts:normal server')
if re.search(output):
    fail('allowed_keysalts policy not applied properly')
realm.run_kadminl('getprinc server')
output = realm.run_kadminl('cpw -randkey -e rc4-hmac:normal,aes256-cts:normal server')
if re.search(output):
    fail('allowed_keysalts policy not applied properly')
realm.run_kadminl('getprinc server')
output = realm.run_kadminl('cpw -randkey -e aes256-cts:normal,rc4-hmac:normal server')
if re.search(output):
    fail('allowed_keysalts policy not applied properly')
realm.run_kadminl('getprinc server')
output = realm.run_kadminl('cpw -randkey -e rc4-hmac:normal,aes128-cts:normal server')
if not re.search(output):
    fail('allowed_keysalts policy not applied properly')
realm.run_kadminl('getprinc server')
output = realm.run_kadminl('cpw -randkey -e rc4-hmac:normal,aes256-cts:normal,aes128-cts:normal server')
if not re.search(output):
    fail('allowed_keysalts policy not applied properly')
realm.run_kadminl('getprinc server')
realm.stop()

success('allowed_keysalts')
