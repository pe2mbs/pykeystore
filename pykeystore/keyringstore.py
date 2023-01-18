import logging
import keyring
from pykeystore.keystore import KeyStore


logger = logging.getLogger('pykeystore.keyringstore')


class KeyringKeystore( KeyStore ):
    """This is a very secure version of the object, whenever the passphrase is needed its retrieved from the keyring
    * Windows:  Windows Credential Manager
    * Linux:    Freedesktop Secret Service or KDE4 & KDE5 KWallet
    * MAC:      Keychain

    """
    def __init__( self, system_name, keyring_name, cihpertest ):
        """Contructor of the keystore

        :param system_name:     system name in the keyring
        :param keyring_name:    username in the keyring
        :param cihpertest:
        """
        KeyStore.__init__( self, cihpertest, keyring.get_password( system_name, keyring_name ) )
        return

    @classmethod
    def loadWithKeyring( cls, filename, system_name, keyring_name ) -> 'KeyringKeystore':
        """Load keystore from file with retrieving the password from the operating system keyring

        :param filename:        The filename of the keystore to be created.
        :param system_name:     system name in the keyring
        :param keyring_name:    username in the keyring
        :return:                Instance of the KeyringKeystore class
        """
        logger.info( f'Loading secure storage "{filename}"' )
        with open( filename, 'rb' ) as stream:
            cihpertext = stream.read()

        return cls( system_name, keyring_name, cihpertext )

    @classmethod
    def createWithKeyring( cls, filename, system_name, keyring_name ) -> 'KeyringKeystore':
        """Create a new keystore with retrieving the password from the operating system keyring.
        The password must be already present in the keyring

        :param filename:        The filename of the keystore to be loaded.
        :param system_name:     system name in the keyring
        :param keyring_name:    username in the keyring
        :return:                Instance of the KeyringKeystore class
        """
        logger.info( f'Creating secure storage "{filename}"' )
        with open( filename, 'wb' ) as stream:
            ciphertext = stream.read()

        return cls( ciphertext, system_name, keyring_name )

    def saveWithKeyring( self, filename, system_name, keyring_name ) -> None:
        """Save the keystore to the file with retrieving the password from the operating system keyring.

        :param filename:        The filename to store the keystore in.
        :param system_name:     system name in the keyring
        :param keyring_name:    username in the keyring
        :return:                None
        """
        logger.info( f'Saving secure storage "{filename}"' )
        KeyStore.save( self, filename, keyring.get_password( system_name, keyring_name ) )
        return

