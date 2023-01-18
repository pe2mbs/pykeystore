from typing import Union
import logging
import os
import json
from cryptography.fernet import Fernet


class InvalidKeystore( Exception ): pass


DEFINE_TESTING      = True
STORE_SECRET        = True

logger = logging.getLogger('pykeystore.storage')


class KeyStore( object ):
    """Python keystore to store passwords, 2FA, private/public keys, certicates, and symmetric keys

    These are stored in an encrypted file that contains a JSON structure. Even in memory the passwords,
    2FA, private and symmetric keys are secondary encrypted.

    """
    def __init__( self, ciphertext: bytes, passphrase: Union[str,bytes] ):
        """Contructor of the keystore

        :param ciphertext:          The encrypted keystore data
        :param passphrase:          The passphrase to open the keystore
        :param keep_passphrase:     True to remember the passphrase within the object (less secure)
        """
        try:
            self.__data:dict    = json.loads( KeyStore.decrypt( KeyStore.correctPassphrase( passphrase ), ciphertext ) )

        except:
            raise InvalidKeystore( 'passphrase wrong or not a valid keystore' )

        if self.__data.get('version') != 1:
            raise InvalidKeystore( 'invalid version' )

        elif self.__data.get( 'signature' ) != 'CE01CE01CE01CE01':
            raise InvalidKeystore( 'invalid signature' )

        # Part of secure programming
        passphrase.zfill(len( passphrase ))
        return

    @staticmethod
    def correctPassphrase( *args ) -> bytes:
        """Join parts of the passphrase to gether as bytes

        :param args:    one or more arguments str or bytes as passphrase.
        :return:        The bytes passphrase.
        """
        result: bytes = b''
        for arg in args:
            result += arg.encode() if isinstance( arg, str ) else arg

        return result

    @staticmethod
    def encrypt( password: bytes, value: Union[bytes,str], encoding: str = "utf8" ) -> Union[bytes,str]:
        """
            Encrypts a string using Fernet
            Args:
                value:      what to encrypt [string/bytes]
                password:   password to use [bytes]
            Returns:
                encrypted string
        """
        if not isinstance( value, bytes ):
            value = value.encode()

        block = Fernet( password ).encrypt( value )
        # Part of secure programming
        password.zfill(len( password ))
        value.zfill( len( value ) )
        return block if encoding == 'bytes' else block.decode( encoding )

    @staticmethod
    def decrypt( password: bytes, value: Union[bytes,str], encoding: str = "utf8" ) -> Union[bytes,str]:
        """
            Encrypts a string using Fernet
            Args:
                value:      what to dencrypt [string/bytes]
                password:   password to use [bytes]
                encoding:   encoding to use for decoding bytes [if None returns bytes]
            Returns:
                decrypted string
        """
        if not isinstance( value, bytes ):
            value = value.encode()

        out = Fernet( password ).decrypt( value )
        # Part of secure programming
        password.zfill(len( password ))
        if encoding:
            return out.decode( encoding )

        return out

    @classmethod
    def create( cls, filename: str, passphrase: Union[str,bytes] ) -> 'KeyStore':
        """Create the initial keystore with default information encoded with the passphrase

        :param filename:        The filename to store the keystore in.
        :param passphrase:      The passphrase of the keystore.
        :param keep_passphrase: True to remember the passphrase within the object (less secure)
        :return:                Instance of the KeyStore class
        """
        data = { 'version': 1,
                 'signature': 'CE01CE01CE01CE01',
                 'passwords': {},
        }
        passphrase          = KeyStore.correctPassphrase( passphrase )
        obj = cls( KeyStore.encrypt( passphrase, json.dumps( data ).encode(), 'bytes' ), passphrase )
        obj.save( filename, passphrase )
        # Part of secure programming
        passphrase.zfill(len( passphrase ))
        return obj

    @classmethod
    def load( cls, filename: str, passphrase: Union[str,bytes] ) -> 'KeyStore':
        """Loads the keystore from disk and decrypts th ekeystore into memory.

        :param filename:        The filename of the keystore.
        :param passphrase:      The passphrase of the keystore.
        :param keep_passphrase: True to remember the passphrase within the object (less secure)
        :return:                Instance of the KeyStore class
        """
        logger.info( f'Opening secure storage "{filename}"' )
        with open( filename, 'rb' ) as stream:
            ciphertext = stream.read()

        result =  cls( ciphertext, passphrase )
        # Part of secure programming
        passphrase.zfill(len( passphrase ))
        return result

    def save( self, filename:str, passphrase: Union[str,bytes,None] ) -> None:
        """Save the keystore to the file

        :param filename:        The filename to store the keystore in.
        :param passphrase:      The passphrase of the keystore.
        :return:                None
        """
        logger.info( f'Saving secure storage "{filename}"' )
        with open( filename, 'wb' ) as stream:
            ciphertext = KeyStore.encrypt( KeyStore.correctPassphrase( passphrase ), json.dumps( self.__data ) )
            stream.write( ciphertext.encode() )

        # Part of secure programming
        passphrase.zfill(len( passphrase ))
        return

    def hasAccount( self, account: str ) -> bool:
        """

        :param account:
        :return:
        """
        return isinstance( self.__data.setdefault( 'passwords', {} ).get( account ), str )

    def setPassword( self, account: str, password: str, passphrase: Union[str,bytes], two_fa = None ):
        """Set the password for am account with optionally the 2FA secret.

        :param account:         Name if the account.
        :param password:        The password to store.
        :param two_fa:          The optional 2FA secret to store.
        :param passphrase:      When Keystore was instanciated with keep_passphrase = False this is mandatory
        :return:                None
        """
        data = self.__data.setdefault( 'passwords', {} ).setdefault( account, {} )
        data[ 'password' ] = KeyStore.encrypt( KeyStore.correctPassphrase( passphrase, account ), password )
        if two_fa is not None:
            data[ '2fa' ] = KeyStore.encrypt( passphrase + account.encode(), two_fa )

        # Part of secure programming
        passphrase.zfill(len( passphrase ))
        password.zfill(len( password ))
        return

    def getPassword( self, account:str, passphrase: Union[str,bytes] ) -> bytes:
        """Retrieve the password from the keystore for the account

        :param account:         Name if the account.
        :param passphrase:      When Keystore was instanciated with keep_passphrase = False this is mandatory
        :return:                None or bytes
        """
        data = self.__data.setdefault( 'passwords', {} ).setdefault( account, {} )
        result = None
        if 'password' in data:
            result = KeyStore.decrypt( passphrase + account.encode(), data.get( 'password' ) )

        # Part of secure programming
        passphrase.zfill(len( passphrase ))
        return result

    def get2fa( self, account:str, passphrase: Union[str,bytes] ):
        """Retrieve the 2FA secret from the keystore for the account

        :param account:         Name if the account.
        :param passphrase:      When Keystore was instanciated with keep_passphrase = False this is mandatory
        :return:
        """
        data = self.__data.setdefault( 'passwords', {} ).setdefault( account, {} )
        result = None
        if '2fa' in data:
            result = KeyStore.decrypt( passphrase + account.encode(), data.get( '2fa' ) )

        # Part of secure programming
        passphrase.zfill(len( passphrase ))
        return result

    def getAccount( self, account:str, passphrase: Union[str,bytes] ):
        """Tetrieve the full account details

        :param account:         Name if the account.
        :param passphrase:      When Keystore was instanciated with keep_passphrase = False this is mandatory
        :return:
        """
        data = self.__data.setdefault( 'passwords', {} ).setdefault( account, {} )
        result = ( None, None, None )
        if '2fa' in data:
            result = (  account,
                        KeyStore.decrypt( passphrase + account.encode(), data.get( 'password' ) ),
                        KeyStore.decrypt( passphrase + account.encode(), data.get( '2fa' ) )
                     )

        elif 'password' in data:
            result = (  account,
                        KeyStore.decrypt( passphrase + account.encode(), data.get( 'password' ) ),
                        None )

        # Part of secure programming
        passphrase.zfill(len( passphrase ))
        return result

    def __checkAsymmetricAlgorithm( self, algo:str ):
        return algo in ( 'RSA', 'DH', 'DSS', 'ECDSA', 'ECDH', 'ELGAMAL', 'PAILLIER', 'CRAMERSHOUP', 'YAK' )

    def hasPrivateKey( self, alias:str, algo:str = 'RSA' ) -> bool:
        """Check if the private key exists in the keystore for the algorithm

        :param alias:           Alias name of the PrivateKey to retrieve
        :param algo:            The algorithm that the key belong to, when omitted RSA is de default
        :return:
        """
        if not self.__checkAsymmetricAlgorithm( algo ):
            return False

        return self.__data.setdefault( algo, {} ).setdefault( 'private', {} ).get( alias ) != None

    def setPrivateKey( self, alias:str, key, algo:str, passphrase: Union[str,bytes] ) -> bool:
        """

        :param alias:
        :param key:
        :param algo:
        :param passphrase:
        :return:
        """
        if not self.__checkAsymmetricAlgorithm( algo ):
            return False

        keys = self.__data.setdefault( algo, {} ).setdefault( 'private', {} )
        keys[ alias ] = KeyStore.encrypt( passphrase + alias.encode(), key )
        # Part of secure programming
        passphrase.zfill( len( passphrase ) )
        key.zfill( len( key ) )
        return True

    def getPrivateKey( self, alias:str, algo:str, passphrase: Union[str,bytes] ):
        """

        :param alias:
        :param algo:
        :param passphrase:
        :return:
        """
        if not self.__checkAsymmetricAlgorithm( algo ):
            return None

        result = KeyStore.decrypt( passphrase + alias.encode(), self.__data.setdefault( algo, {} ).setdefault( 'private', {} ).get( alias ) )
        # Part of secure programming
        passphrase.zfill( len( passphrase ) )
        return result

    def hasPublicKey( self, alias:str, algo:str = 'RSA' ) -> bool:
        """

        :param alias:
        :param algo:
        :return:
        """
        if not self.__checkAsymmetricAlgorithm( algo ):
            return False

        return self.__data.setdefault( algo, {} ).setdefault( 'public', {} ).get( alias ) != None

    def setPublicKey( self, alias:str, key = None, algo:str = 'RSA' ) -> bool:
        """

        :param alias:
        :param key:
        :param algo:
        :return:
        """
        if not self.__checkAsymmetricAlgorithm( algo ):
            return False

        keys = self.__data.setdefault( algo, {} ).setdefault( 'public', {} )
        keys[ alias ] = key
        return True

    def getPublicKey( self, alias:str, algo:str = 'RSA' ):
        """

        :param alias:
        :param algo:
        :return:
        """
        if not self.__checkAsymmetricAlgorithm( algo ):
            return None

        return self.__data.setdefault( algo, {} ).setdefault( 'public', {} ).get( alias )

    def hasCertificate( self, alias:str, algo:str = 'RSA' ) -> bool:
        """

        :param alias:
        :param algo:
        :return:
        """
        if not self.__checkAsymmetricAlgorithm( algo ):
            return False

        return self.__data.setdefault( algo, {} ).setdefault( 'cerificate', {} ).get( alias ) != None

    def setCertificate( self, alias:str, cert, algo:str = 'RSA' ) -> bool:
        """

        :param alias:
        :param cert:
        :param algo:
        :return:
        """
        if not self.__checkAsymmetricAlgorithm( algo ):
            return False

        keys = self.__data.setdefault( algo, {} ).setdefault( 'cerificate', {} )
        keys[ alias ] = cert
        return True

    def getCertificate( self, alias:str, algo:str = 'RSA' ) -> Union[bytes,None]:
        """

        :param alias:
        :param algo:
        :return:
        """
        if not self.__checkAsymmetricAlgorithm( algo ):
            return None

        return self.__data.setdefault( algo, {} ).setdefault( 'public', {} ).get( alias )

    def __checkSymmetricAlgorithm( self, algo:str ):
        return algo in ( 'DES', 'AES', 'IDEA', 'BLOWFISH', 'RC4', 'RC5', 'RC6' )

    def hasEncriptioneKey( self, alias:str, algo:str ) -> bool:
        """

        :param alias:
        :param algo:
        :return:
        """
        if not self.__checkSymmetricAlgorithm( algo ):
            return False

        return self.__data.setdefault( algo, {} ).get( alias ) != None

    def setEncriptioneKey( self, alias:str, algo:str, key, passphrase: Union[str,bytes] ):
        """

        :param alias:
        :param algo:
        :param key:
        :param passphrase:
        :return:
        """
        if not self.__checkSymmetricAlgorithm( algo ):
            return False

        if algo == 'DES':
            if isinstance( key, bytes ) and len( key ) in ( 8, 16 ):
                raise
            elif isinstance( key, str ) and len( key ) in ( 16, 32 ):
                raise
        elif algo == 'AES':
            if isinstance( key, bytes ) and len( key ) in ( 128, 192, 256 ):
                raise
            elif isinstance( key, str ) and len( key ) in ( 256, 324, 512 ):
                raise

        self.__data.setdefault( algo, {} )[ alias ] = KeyStore.encrypt( passphrase + alias.encode(), key )
        # Part of secure programming
        passphrase.zfill( len( passphrase ) )
        key.zfill( len( key ) )
        return True

    def getEncriptioneKey( self, algo:str, alias:str, passphrase: Union[str,bytes] ) -> Union[None,bytes]:
        """

        :param algo:
        :param alias:
        :param passphrase:
        :return:
        """
        if not self.__checkSymmetricAlgorithm( algo ):
            return None

        result = KeyStore.decrypt( passphrase + alias.encode(), self.__data.setdefault( algo, {} ).get( alias ) )
        passphrase.zfill( len( passphrase ) )
        return result

    if DEFINE_TESTING:
        def dump( self ):
            print( json.dumps( self.__data, indent = 4 ) )
            return


