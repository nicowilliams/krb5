.. _kpropd(8):

kpropd
===========


SYNOPSIS
----------

**kpropd**
[**-r** *realm*]
[**-a** *acl_file*]
[**-f** *slave_dumpfile*]
[**-F** *principal_database*]
[**-p** *kdb5_util_prog*]
[**-P** *port*]
[**-d**]

DESCRIPTION
-------------

Where incremental propagation is not used, kpropd is commonly invoked
out of inetd(8) as a nowait service.  This is done by adding a line to
the ``/etc/inetd.conf`` file which looks like this:

When the slave receives a kprop request from the master, *kpropd* accepts the dumped KDC database and places it in a file, 
and then runs :ref:`kdb5_util(8)` to load the dumped database into the active database which is used by :ref:`krb5kdc(8)`.  
Thus, the master Kerberos server can use :ref:`kprop(8)` to propagate its database to the slave slavers.  
Upon a successful download of the KDC database file, the slave Kerberos server will have an up-to-date KDC database.

Normally, *kpropd* is invoked out of inetd(8).  This is done by adding a line to the *inetd.conf* file which looks like this::

       kprop     stream    tcp  nowait    root /usr/local/sbin/kpropd   kpropd

kpropd can also run as a standalone daemon.  This is required for
incremental propagation.  But this is also useful for debugging
purposes.

However, *kpropd* can also run as a standalone daemon, if the *-S* option is turned on.  
This is done for debugging purposes, or if for some reason the system administrator just doesn't want to run it out of inetd(8).

When the slave periodically requests incremental updates, *kpropd* updates its *principal.ulog* file with any updates from the master.  
:ref:`kproplog(8)` can be used to view a summary of the update entry log on the slave KDC.  
Incremental propagation is not enabled by default; it can be enabled using the *iprop_enable* and *iprop_slave_poll* settings in :ref:`kdc.conf`.  
The principal "kiprop/slavehostname\@REALM" (where "slavehostname" is the name of the slave KDC host, 
and "REALM" is the name of the Kerberos realm) must be present in the slave's keytab file.

OPTIONS
--------

**-r** *realm*
    Specifies the realm of the master server.

**-f** *file*
    Specifies the filename where the dumped principal database file is
    to be stored; by default the dumped database file is |kdcdir|\
    ``/from_master``.

**-p**
    Allows the user to specify the pathname to the :ref:`kdb5_util(8)`
    program; by default the pathname used is |sbindir|\
    ``/kdb5_util``.

**-S**
    [DEPRECATED] Enable standalone mode.  Normally kpropd is invoked by
    inetd(8) so it expects a network connection to be passed to it
    from inetd(8).  If the **-S** option is specified, or if standard
    input is not a socket, kpropd will put itself into the background,
    and wait for connections on port 754 (or the port specified with the
    **-P** option if given).

       **-f** *file*
              Specifies the filename where the dumped principal database file is to be stored; by default the dumped database file
              /usr/local/var/krb5kdc/from_master.

       **-p**
              Allows the user to specify the pathname to the :ref:`kdb5_util(8)` program; by default the pathname used is /usr/local/sbin/kdb5_util.

       **-S**     
              Turn on standalone mode.  Normally, *kpropd* is invoked out of inetd(8) so it expects a network connection to be passed to it from inetd(8).
              If the *-S* option is specified, *kpropd* will put itself into the background, 
              and wait for connections to the *krb5_prop* port specified in  /etc/services.  

       **-d**     
              Turn on debug mode.  In this mode, if the *-S* option is selected, *kpropd* will not detach itself from the current job
              and run in the background.  Instead, it will run in the foreground and print out debugging messages during the database propagation.

       **-P**     
               Allow for an alternate port number for *kpropd* to listen on. This is only useful if the program is run in standalone mode.

       **-a**     
              Allows the user to specify the path to the *kpropd.acl* file; by default the path used is /usr/local/var/krb5kdc/kpropd.acl.

FILES
---------

*kpropd.acl*  
            Access file for *kpropd*; the default location is /usr/local/var/krb5kdc/kpropd.acl.  
            Each entry is a line containing the principal of a host from which the local machine will allow Kerberos database propagation via :ref:`kprop(8)`.

SEE ALSO
----------

kprop(8), kdb5_util(8), krb5kdc(8), inetd(8)


