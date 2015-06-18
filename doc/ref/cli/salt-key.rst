============
``salt-key``
============

Synopsis
========

.. code-block:: bash

    salt-key [ options ]

Description
===========

Salt-key executes simple management of Salt server public keys used for
authentication.


Key States
==========
Minion-Keys on a master have four states they can be in.

Pre
A minion has sent its public key to the master and the key was placed in
'minions_pre'. It has to be accepted to allow the minion to
authenticate.

Accepted
A minion-key was accepted and moved from 'minions_pre' to 'minions'. All
accepted minions are allowed to authenticate and retrieve their states,
files, etc. from the master.

Rejected
To disallow specific minions to authenticate, their keys can be moved into
'minions_rejected' and the master will deny their authentication attempts.

Denied
If a minion was denied by the master due to a key-mismatch, the key sent
by the minion will be placed in 'minions_denied' while leaving the key in
'minions' untouched. This may happen when reinstalling a minion without
saving the old key-pair or when multiple minions have the same minions-id.

This has to be resolved manually as is not possible for the master to know,
which of the two keys the correct one is.


Options
=======

.. program:: salt-key

.. include:: _includes/common-options.rst

.. option:: -u USER, --user=USER

    Specify user to run salt-key

.. option:: --hard-crash

    Raise any original exception rather than exiting gracefully. Default is
    False.

.. option:: -q, --quiet

   Suppress output

.. option:: -y, --yes

   Answer 'Yes' to all questions presented, defaults to False

.. option:: --rotate-aes-key=ROTATE_AES_KEY

    Setting this to False prevents the master from refreshing the key session
    when keys are deleted or rejected, this lowers the security of the key
    deletion/rejection operation. Default is True.

.. include:: _includes/logging-options.rst
    :end-before: start-console-output
.. include:: _includes/logging-options.rst
    :start-after: stop-console-output
.. |logfile| replace:: /var/log/salt/minion
.. |loglevel| replace:: ``warning``

.. include:: _includes/output-options.rst

Actions
-------

.. option:: -l ARG, --list=ARG

    List the public keys. The args ``pre``, ``un``, and ``unaccepted`` will
    list unaccepted/unsigned keys. ``acc`` or ``accepted`` will list
    accepted/signed keys. ``rej`` or ``rejected`` will list rejected keys.
    Finally, ``all`` will list all keys.

.. option:: -L, --list-all

    List all public keys. (Deprecated: use ``--list all``)

.. option:: -a ACCEPT, --accept=ACCEPT

    Accept the specified public key (use --include-all to match rejected keys
    in addition to pending keys). Globs are supported.

.. option:: -A, --accept-all

    Accepts all pending keys.

.. option:: -r REJECT, --reject=REJECT

    Reject the specified public key (use --include-all to match accepted keys
    in addition to pending keys). Globs are supported.

.. option:: -R, --reject-all

    Rejects all pending keys.

.. option:: --include-all

    Include non-pending keys when accepting/rejecting.

.. option:: -p PRINT, --print=PRINT

    Print the specified public key.

.. option:: -P, --print-all

    Print all public keys

.. option:: -d DELETE, --delete=DELETE

    Delete the specified key. Globs are supported.

.. option:: -D, --delete-all

    Delete all keys.

.. option:: -f FINGER, --finger=FINGER

    Print the specified key's fingerprint.

.. option:: -F, --finger-all

    Print all keys' fingerprints.


Key Generation Options
-----------------------

.. option:: --gen-keys=GEN_KEYS

   Set a name to generate a keypair for use with salt

.. option:: --gen-keys-dir=GEN_KEYS_DIR

   Set the directory to save the generated keypair.  Only works
   with 'gen_keys_dir' option; default is the current directory.

.. option:: --keysize=KEYSIZE

   Set the keysize for the generated key, only works with
   the '--gen-keys' option, the key size must be 2048 or
   higher, otherwise it will be rounded up to 2048. The
   default is 2048.

.. option:: --gen-signature

    Create a signature file of the masters public-key named
    master_pubkey_signature. The signature can be send to a minion in the
    masters auth-reply and enables the minion to verify the masters public-key
    cryptographically. This requires a new signing-key- pair which can be
    auto-created with the --auto-create parameter.

.. option:: --priv=PRIV

    The private-key file to create a signature with

.. option:: --signature-path=SIGNATURE_PATH

    The path where the signature file should be written

.. option:: --pub=PUB

    The public-key file to create a signature for

.. option:: --auto-create

    Auto-create a signing key-pair if it does not yet exist

See also
========

:manpage:`salt(7)`
:manpage:`salt-master(1)`
:manpage:`salt-minion(1)`