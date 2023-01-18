from typing import Union
import logging
import os
import json
from cryptography.fernet import Fernet
from pykeystore.keystore import KeyStore

class InvalidKeystore( Exception ): pass


DEFINE_TESTING      = True


logger = logging.getLogger('pykeystore.keystorex')


class KeyStoreEx( KeyStore ):
    """This object is less secure as the passphrase is mainted in the object

    """
    def __init__( self, ciphertext: bytes, passphrase: Union[str,bytes] ):
        """Contructor of the keystore

        :param ciphertext:          The encrypted keystore data
        :param passphrase:          The passphrase to open the keystore
        """
        self.__passphrase   = passphrase
        KeyStore.__init__( self, ciphertext, passphrase )
        return

    def setPassword( self, account: str, password: str, two_fa = None ):            # noqa ignore function signature different
        """Set the password for am account with optionally the 2FA secret.

        :param account:         Name if the account.
        :param password:        The password to store.
        :param two_fa:          The optional 2FA secret to store.
        :return:                None
        """
        KeyStore.setPassword( self, account, password, self.__passphrase, two_fa )
        return

    def getPassword( self, account:str ) -> bytes:                                  # noqa ignore function signature different
        """Retrieve the password from the keystore for the account

        :param account:         Name if the account.
        :param passphrase:      When Keystore was instanciated with keep_passphrase = False this is mandatory
        :return:                None or bytes
        """
        return KeyStore.getPassword( self, account, self.__passphrase )

    def get2fa( self, account:str ):                                                # noqa ignore function signature different
        """Retrieve the 2FA secret from the keystore for the account

        :param account:         Name if the account.
        :param passphrase:      When Keystore was instanciated with keep_passphrase = False this is mandatory
        :return:
        """
        return KeyStore.get2fa( self, account, self.__passphrase )

    def getAccount( self, account:str ):                                            # noqa ignore function signature different
        """Tetrieve the full account details

        :param account:         Name if the account.
        :param passphrase:      When Keystore was instanciated with keep_passphrase = False this is mandatory
        :return:
        """
        return KeyStore.getAccount( self, account, self.__passphrase )

    def setPrivateKey( self, alias:str, key, algo:str ) -> bool:                    # noqa ignore function signature different
        """

        :param alias:
        :param key:
        :param algo:
        :param passphrase:
        :return:
        """
        return KeyStore.setPrivateKey( self, alias, key, algo, self.__passphrase )

    def getPrivateKey( self, alias:str, algo:str ):                                 # noqa ignore function signature different
        """

        :param alias:
        :param algo:
        :param passphrase:
        :return:
        """
        return KeyStore.getPrivateKey( self, alias, algo, self.__passphrase )

    def setEncriptioneKey( self, alias:str, algo:str, key ):                        # noqa ignore function signature different
        """

        :param alias:
        :param algo:
        :param key:
        :param passphrase:
        :return:
        """
        return KeyStore.setEncriptioneKey( self, alias, algo, key, self.__passphrase )

    def getEncriptioneKey( self, algo:str, alias: str ) -> Union[None,bytes]:           # noqa ignore function signature different
        """

        :param algo:
        :param alias:
        :param passphrase:
        :return:
        """
        return KeyStore.getEncriptioneKey( self, alias, algo, self.__passphrase )
