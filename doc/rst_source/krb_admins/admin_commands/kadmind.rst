.. _kadmind(8):

kadmind
==========

SYNOPSIS
--------

**kadmind**
[**-x** *db_args*]
[**-r** *realm*]
[**-m**]
[**-nofork**]
[**-port** *port-number*]
[**-P** *pid_file*]
[**-p** *kdb5_util_path*]
[**-C** *kprop_path*]
[**-F** *dump_file*]

DESCRIPTION
-----------

This command starts the KADM5 administration server. If the database is db2, the administration server runs on the master Kerberos server, 
which stores the KDC prinicpal database and the KADM5 policy database. If the database is LDAP, the administration server and
the KDC server need not run on the same machine.  *kadmind* accepts remote requests to administer the information in these databases.
Remote requests are sent, for example, by kadmin(8) and the kpasswd(1) command, both of which are clients of *kadmind*.

*kadmind* requires a number of configuration files to be set up in order for it to work:

:ref:`kdc.conf`  
            The KDC configuration file contains configuration informatin for the KDC and the KADM5 system.  *kadmind* understands a number
            of  variable  settings in this file, some of whch are mandatory and some of which are optional.
            See the CONFIGURATION VALUES section below.

*keytab*    
            Kadmind requires a keytab containing correct entries for the kadmin/admin and kadmin/changepw principals for every realm that
            *kadmind* will answer requests for.  The keytab can be created with the kadmin(8) client.
            The location of the keytab is determined by the *admin_keytab* configuration variable (see CONFIGURATION VALUES).

*ACL* file 
            *kadmind*'s *ACL* (access control list) tells it which principals are allowed to perform KADM5 administration actions.
            The  path of  the *ACL* file is specified via the acl_file configuration variable (see CONFIGURATION VALUES).
            The syntax of the *ACL* file is specified in the *ACL* FILE SYNTAX section below.
            
            If the *kadmind*'s ACL file is modified, the *kadmind* daemon needs to be restarted for changes to take effect.

After the server begins running, it puts itself in the background and disassociates itself from its controlling terminal.

*kadmind* can be configured for incremental database propagation.  Incremental propagation allows slave KDC servers to receive  principal
and  policy  updates  incrementally instead of receiving full dumps of the database.  This facility can be enabled in the :ref:`kdc.conf` file
with the *iprop_enable* option.  See the :ref:`kdc.conf` documentation for other options for tuning incremental propagation parameters.
Incremental propagation requires the principal "kiprop/MASTER\@REALM" i
(where MASTER is the master KDC's canonical host name, and REALM the realm name) to be registered in the database.


OPTIONS
-------

**-r** *realm*
    specifies the realm that kadmind will serve; if it is not
    specified, the default realm of the host is used.

**-m**
    causes the master database password to be fetched from the
    keyboard (before the server puts itself in the background, if not
    invoked with the **-nofork** option) rather than from a file on
    disk.

**-nofork**
    causes the server to remain in the foreground and remain
    associated to the terminal.  In normal operation, you should allow
    the server to place itself in the background.

**-port** *port-number*
    specifies the port on which the administration server listens for
    connections.  The default port is determined by the
    **kadmind_port** configuration variable in :ref:`kdc.conf(5)`.

**-P** *pid_file*
    specifies the file to which the PID of kadmind process should be
    written after it starts up.  This file can be used to identify
    whether kadmind is still running and to allow init scripts to stop
    the correct process.

**-p** *kdb5_util_path*
    specifies the path to the kdb5_util command to use when dumping the
    KDB in response to full resync requests when iprop is enabled.

**-C** *kprop_path*
    specifies the path to the kprop command to use to send full dumps
    to slaves in response to full resync requests.

**-F** *dump_file*
    specifies the file path to be used for dumping the KDB in response
    to full resync requests when iprop is enabled.

**-x** *db_args*
    specifies database-specific arguments.

    Options supported for LDAP database are:

        **-x nconns=**\ *number_of_connections*
            specifies the number of connections to be maintained per
            LDAP server.

        **-x host=**\ *ldapuri*
            specifies the LDAP server to connect to by URI.

        **-x binddn=**\ *binddn*
            specifies the DN of the object used by the administration
            server to bind to the LDAP server.  This object should
            have read and write privileges on the realm container, the
            principal container, and the subtree that is referenced by
            the realm.

        **-x bindpwd=**\ *bind_password*
            specifies the password for the above mentioned binddn.
            Using this option may expose the password to other users
            on the system via the process list; to avoid this, instead
            stash the password using the **stashsrvpw** command of
            :ref:`kdb5_ldap_util(8)`.

SEE ALSO
-----------

kpasswd(1), kadmin(8), kdb5_util(8), kadm5_export(8), kadm5_import(8), kdb5_ldap_util(8)


