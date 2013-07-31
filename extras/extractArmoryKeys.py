#! /usr/bin/python
import sys

sys.path.append('..')
sys.path.append('.')

from armoryengine import *
import getpass
from sys import argv
import os

# Do not ever access the same wallet file from two different processes at the same time
print '\n'
raw_input('PLEASE CLOSE ARMORY BEFORE RUNNING THIS SCRIPT!  (press enter to continue)\n')

if len(argv) < 2:
    print 'USAGE: %s <wallet file>' % argv[0]
    exit(0)

wltfile = argv[1]

if not os.path.exists(wltfile):
    print 'Wallet file was not found: %s' % wltfile

wlt = PyBtcWallet().readWalletFile(wltfile)

# If the wallet is encrypted, get the passphrase
if wlt.useEncryption:
    print 'Please enter your passphrase to unlock your wallet: '
    for ntries in range(3):
        passwd = SecureBinaryData(getpass.getpass('Wallet Passphrase: '))
        if wlt.verifyPassphrase(passwd):
            break;

        print 'Passphrase was incorrect!'
        if ntries == 2:
            print 'Wallet could not be unlocked.  Aborting.'
            exit(0)

    print 'Correct Passphrase.  Unlocking wallet...'
    wlt.unlock(securePassphrase=passwd)
    passwd.destroy()

dumpfilename = os.path.split(os.path.splitext(wltfile)[0] + 'keys.txt')[1]

print 'Writing private keys to ' + dumpfilename

dumpfile = open(dumpfilename, 'w')
for addr in [a for a in wlt.getAddrList() if a.hasPrivKey()]:
    dumpfile.write(binary_to_base58(addr.serializePlainPrivateKey()) + '\n')