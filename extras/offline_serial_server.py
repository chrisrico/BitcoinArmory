import sys
from twisted.python.dist import build_scripts_twisted

sys.path.append('..')

from armoryengine import *
import os
import time
import getpass
import zlib

class OfflineSerialServer:
   exitCode = None

   def __init__(self):
      if len(CLI_ARGS) < 2:
         print 'USAGE: %s <serial device> <serial rate>' % argv[0]
         exit()

      self.wallets = dict([self.loadWallet(wlt) for wlt in os.listdir(ARMORY_HOME_DIR) if
                           wlt.endswith('.wallet') and not wlt.endswith('_backup.wallet')])

      self.device = CLI_ARGS[0]
      self.rate = int(CLI_ARGS[1])

      self.messageHandlers = {
         bool: self.isConnectedChanged,
         pb.SignatureRequest: self.handleSignatureRequest,
         pb.OnlineWalletRequest: self.handleOnlineWalletRequest,
         pb.CreateWallet: self.handleCreateWallet,
         pb.Reset: self.handleReset
      }

      self.conn = PySerialConnection(self.device, self.rate, self.handleMessage)

   def __enter__(self):
      self.conn.open()
      print 'Serial port open'
      return self

   def __exit__(self, exc_type, exc_val, exc_tb):
      self.conn.close()
      print 'Serial port closed'

   def writeInfo(self, info):
      msg = pb.Notification()
      msg.type = msg.INFORMATION
      msg.message = info
      self.conn.write(msg)

   def writeError(self, error, critical=False):
      msg = pb.Notification()
      if critical:
         msg.type = msg.CRITICAL_ERROR
      else:
         msg.type = msg.ERROR
      msg.message = error
      self.conn.write(msg)

   def loadWallet(self, file):
      wlt = PyBtcWallet().readWalletFile(os.path.join(ARMORY_HOME_DIR, file))
      print 'Loaded wallet %s (%s)' % (wlt.labelName, wlt.uniqueIDB58)
      return (wlt.uniqueIDB58, wlt)

   def extendWallet(self, wlt, index):
      while wlt.lastComputedChainIndex < index:
         wlt.computeNextAddress()

   def getPassphrase(self, prompt):
      return SecureBinaryData(getpass.getpass(prompt))

   def unlockWallet(self, wlt):
      # If the wallet is encrypted, get the passphrase
      if wlt.useEncryption and wlt.isLocked:
         for ntries in range(3):
            self.writeInfo('Wallet passphrase required')
            passwd = self.getPassphrase('Wallet Passphrase: ')
            if wlt.verifyPassphrase(passwd):
               break;
            else:
               self.writeError('Incorrect passphrase')

            if ntries == 2:
               self.writeError('Wallet could not be unlocked', True)
               return

         self.writeInfo('Unlocking wallet')
         wlt.unlock(securePassphrase=passwd)
         passwd.destroy()

   def handleMessage(self, msg):
      handler = self.messageHandlers.get(type(msg))
      if handler:
         handler(msg)

   def isConnectedChanged(self, isConnected):
      if isConnected:
         print 'Online wallet connected'
      else:
         print 'Online wallet disconnected'

   def signTxDistProposal(self, wlt, request):
      try:
         txdp = PyTxDistProposal().unserializeAscii(request.txDP)
         print 'Received unsigned tx proposal %s' % txdp.uniqueB58

         found = 0
         for a160 in txdp.inAddr20Lists:
            if wlt.hasAddr(a160[0]):
               found += 1

         if found == 0:
            self.writeError('Unable to find any signing keys', True)
            return
         elif found < len(txdp.inAddr20Lists) and request.type == request.FULL:
            self.writeError('Unable to find all signing keys', True)
            return

         self.unlockWallet(wlt)

         try:
            wlt.signTxDistProposal(txdp)
            if not request.keepWalletUnlocked:
               wlt.lock()

            if not txdp.checkTxHasEnoughSignatures() and request.type == request.FULL:
               self.writeError('Transaction has not enough signatures', True)
            else:
               msg = pb.SignatureResponse()
               msg.txDP = txdp.serializeAscii()
               self.conn.write(msg)
               print 'Sent signed tx proposal'

         except WalletLockError:
            self.writeError('Wallet is somehow still locked')
         except:
            self.writeError('Unknown signing error')

      except IndexError:
         self.writeError('Invalid transaction distribution proposal')

   def handleSignatureRequest(self, msg):
      wlt = self.wallets.get(msg.wallet.uniqueIDB58)
      if wlt:
         idx = msg.wallet.lastComputedChainIndex
         if idx > wlt.lastComputedChainIndex:
            self.extendWallet(wlt, idx)
         self.signTxDistProposal(msg)
      else:
         self.writeError('Cannot find wallet with id %s' % msg.wallet.uniqueIDB58, True)

   def buildOnlineWalletResponse(self, wltmsg, wlt, metadataOnly):
      wltmsg.uniqueIDB58 = wlt.uniqueIDB58
      wltmsg.labelName = wlt.labelName
      wltmsg.labelDescr = wlt.labelDescr

      if not metadataOnly:
         copy = wlt.forkOnlineWallet('.temp_wallet')
         os.remove('.temp_wallet')
         packer = BinaryPacker()
         copy.packHeader(packer)
         data = packer.getBinaryString()
         for addr160,addrObj in copy.addrMap.iteritems():
            if not addr160=='ROOT':
               data += '\x00' + addr160 + addrObj.serialize()

            for hashVal,comment in copy.commentsMap.iteritems():
               twoByteLength = int_to_binary(len(comment), widthBytes=2)
               if len(hashVal)==20:
                  typestr = int_to_binary(WLT_DATATYPE_ADDRCOMMENT)
                  data += typestr + hashVal + twoByteLength + comment
               elif len(hashVal)==32:
                  typestr = int_to_binary(WLT_DATATYPE_TXCOMMENT)
                  data += typestr + hashVal + twoByteLength + comment

         wltmsg.packedBytes = zlib.compress(data)

   def handleOnlineWalletRequest(self, msg):
      response = pb.OnlineWalletResponse()
      for wlt in self.wallets.itervalues():
         if not msg.uniqueIDB58 or msg.uniqueIDB58 == wlt.uniqueIDB58:
            self.buildOnlineWalletResponse(response.wallets.add(), wlt, msg.metadataOnly)
      self.conn.write(response)

   def handleCreateWallet(self, msg):
      passwd = None
      if msg.useEncryption:
         self.writeInfo('Input passphrase')
         passwd = self.getPassphrase('Input passphrase: ')
         self.writeInfo('Confirm passphrase')
         passwdConfirm = self.getPassphrase('Confirm passphrsae: ')
         if passwd.getHash160() != passwdConfirm.getHash160():
            self.writeError('Passphrases do not match!', True)
            return

      wlt = PyBtcWallet().createNewWallet(
         withEncrypt=msg.withEncrypt,
         securePassphrase=passwd,
         kdfTargSec=msg.kdfSec,
         kdfMaxMem=msg.kdfBytes,
         shortLabel=msg.name,
         longLabel=msg.descr,
         doRegisterWithBDM=False)

      response = pb.OnlineWalletResponse()
      self.buildOnlineWalletResponse(response.wallets.add(), wlt, False)
      self.conn.write(response)

   def handleReset(self, msg):
      if msg.shutdown:
         self.exitCode = 1
      else:
         self.exitCode = 0

exitCode=0
while exitCode == 0:
   with OfflineSerialServer() as server:
      try:
         while not server.exitCode:
            time.sleep(1)
         exitCode = server.exitCode
      except KeyboardInterrupt:
         exitCode = 2
exit(exitCode)