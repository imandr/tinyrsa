Minimalistic but useful implementation of public key encryption suite
=====================================================================

The package includes a Pyhton library and a command line script, 
which implements basic public key encryption functions:

* Key pair generation 
* Public key extraction
* File encryption and decryption
* Digital signature generation and verification

Installation
------------

After cloning the repository, run the setup.py script:

.. code-block:: shell

    $ git clone https://github.com/imandr/tinyrsa.git
    $ cd tinyrsa
    $ python setup.py install --user
    
    
Command line script usage
-------------------------

::

    $ tinyrsa generate [-s <key size, bits>] -k <keypair file>
              public -k <keypair file> [-o <public key file>]
              encrypt -k <keypair or public key file> <input file> <output file>
              decrypt -k <keypair or public key file> <input file> <output file>
              sign -k <keypair file> <input file> (<signature file>|-)
              verify -k <keypair or public key file> <input file> <signature file>


Test
----

.. code-block:: shell

    $ cd test
    $ ./test.sh
    
