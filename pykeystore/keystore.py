from typing import Union
import logging
import chardet
import json
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet
import cryptography.hazmat.backends.openssl.rsa as RSA


class InvalidKeystore( Exception ): pass
class InvalidParameter( Exception ): pass


DEFINE_TESTING      = True
STORE_SECRET        = True

logger = logging.getLogger('pykeystore.storage')


class KeyStore( object ):
    """Python keystore to store passwords, 2FA, private/public keys, certicates, and symmetric keys

    These are stored in an encrypted file that contains a JSON structure. Even in memory the passwords,
    2FA, private and symmetric keys are secondary encrypted.

    """
    __UNIQUE_SIGNATURE_ID   = 'A83CCDA8-7814-4D74-A3EB-F4E239167F87'
    __VERSION               = 1

    def __init__( self, ciphertext: bytes, passphrase: Union[str,bytes] ):
        """Contructor of the keystore

        :param ciphertext:          The encrypted keystore data
        :param passphrase:          The passphrase to open the keystore
        """
        try:
            self.__data:dict    = json.loads( KeyStore.decrypt( KeyStore.correctPassphrase( passphrase ), ciphertext ) )

        except:
            raise InvalidKeystore( 'passphrase wrong or not a valid keystore' )

        if self.__data.get('version') != KeyStore.__VERSION:
            raise InvalidKeystore( 'invalid version' )

        elif self.__data.get( 'signature' ) != KeyStore.__UNIQUE_SIGNATURE_ID:
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
        """Encrypts a string using Fernet

        :param value:       what to encrypt [string/bytes]
        :param password:    password to use [bytes]
        :param encoding:    encoding to use for encoding/decoding bytes [if None returns bytes]
        :return:            encrypted string
        """
        if not isinstance( value, bytes ):
            value = value.encode( encoding )

        block = Fernet( password ).encrypt( value )
        # Part of secure programming
        password.zfill(len( password ))
        value.zfill( len( value ) )
        return block if encoding in ( None, 'bytes' ) else block.decode( encoding )

    @staticmethod
    def decrypt( password: bytes, value: Union[bytes,str], encoding: str = "utf8" ) -> Union[bytes,str]:
        """Encrypts a string using Fernet

        :param password:    password to use [bytes]
        :param value:       what to dencrypt [string/bytes]
        :param encoding:    encoding to use for encoding/decoding bytes [if None returns bytes]
        :return:            decrypted string in UTF-8 format/bytes unformatted
        """
        if not isinstance( value, bytes ):
            value = value.encode( encoding )

        out = Fernet( password ).decrypt( value )
        # Part of secure programming
        password.zfill(len( password ))
        if encoding not in ( None, 'bytes' ):
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
        data = { 'version': KeyStore.__VERSION,
                 'signature': KeyStore.__UNIQUE_SIGNATURE_ID,
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

    def setPassword( self, account: str, password: str, passphrase: Union[str,bytes], two_fa: Union[str,None] = None ):
        """Set the password for am account with optionally the 2FA secret.

        :param account:         Name if the account.
        :param password:        The password to store.
        :param two_fa:          The optional 2FA secret to store.
        :param passphrase:      The passphrase of the keystore.
        :return:                None
        """
        data = self.__data.setdefault( 'passwords', {} ).setdefault( account, {} )
        data[ 'password' ] = KeyStore.encrypt( KeyStore.correctPassphrase( passphrase, account ), password )
        if two_fa is not None:
            data[ '2fa' ] = KeyStore.encrypt( passphrase + account.encode(), two_fa )

        # Part of secure programming
        passphrase.zfill(len( passphrase ))
        password.zfill(len( password ))
        if two_fa is not None:
            two_fa.zfill(len( two_fa ))

        return

    def set2fa( self, account: str, two_fa: str, passphrase: Union[str,bytes] ):
        """Set the password for am account with optionally the 2FA secret.

        :param account:         Name if the account.
        :param two_fa:          The optional 2FA secret to store.
        :param passphrase:      The passphrase of the keystore.
        :return:                None
        """
        data = self.__data.setdefault( 'passwords', {} ).setdefault( account, {} )
        data[ '2fa' ] = KeyStore.encrypt( passphrase + account.encode(), two_fa )

        # Part of secure programming
        passphrase.zfill(len( passphrase ))
        two_fa.zfill(len( two_fa ))
        return

    def getPassword( self, account:str, passphrase: Union[str,bytes] ) -> bytes:
        """Retrieve the password from the keystore for the account

        :param account:         Name if the account.
        :param passphrase:      The passphrase of the keystore.
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
        :param passphrase:      The passphrase of the keystore.
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
        :param passphrase:      The passphrase of the keystore.
        :return:
        """
        def secured_data( data, name ):
            result = data.get( name )
            if result is None:
                return result

            return KeyStore.decrypt( passphrase + account.encode(), result )

        data = self.__data.setdefault( 'passwords', {} ).setdefault( account, {} )
        result = ( account, secured_data( data, 'password' ), secured_data( data, '2fa' ) )
        # Part of secure programming
        passphrase.zfill(len( passphrase ))
        return result

    def __checkAsymmetricAlgorithm( self, algo:str ):
        return algo in ( 'RSA', 'DH', 'DSS', 'ECDSA', 'ECDH', 'ELGAMAL', 'PAILLIER', 'CRAMERSHOUP', 'YAK' )

    def hasPrivateKey( self, alias:str, algo:str = 'RSA' ) -> bool:
        """Check if the private key exists in the keystore for the algorithm

        :param alias:           Alias name of the private key to check
        :param algo:            The algorithm that the key belong to, when omitted RSA is de default
        :return:
        """
        if not self.__checkAsymmetricAlgorithm( algo ):
            return False

        return self.__data.setdefault( algo, {} ).setdefault( alias, {} ).get( 'private' ) != None

    def setPrivateKey( self, alias:str, key: Union[str,bytes,RSA.RSAPrivateKey], algo:str, passphrase: Union[str,bytes] ) -> bool:
        """Set the value of the private key in the keystore for the algorithm, this has a second level of encryption.

        :param alias:           Alias name of the private key to store
        :param key:             The private key to store in the keystore, this should be in UTF-8 encoding
                                to avoid conversion issues. Best to provide the private key in PEM format.
        :param algo:            The algorithm that the key belong to
        :param passphrase:      The passphrase of the keystore or passphrase that belongs to the private key.
        :return:
        """
        if not self.__checkAsymmetricAlgorithm( algo ):
            return False

        enc = 'utf-8'
        fmt = 'raw'
        if isinstance( key, str ):
            if key.startswith( '-----BEGIN ' ):
                fmt = 'PEM'

        elif isinstance( key, bytes ):
            if key.startswith( b'-----BEGIN ' ):
                enc = 'bytes'
                fmt = 'PEM'

        elif isinstance( key, RSA.RSAPrivateKey ):
            key = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
            enc = 'utf-8'
            fmt = 'RSA._RSAPrivateKey'

        else:
            raise InvalidParameter( 'key' )

        skey = self.__data.setdefault( algo, {} ).setdefault( alias, {} ).setdefault( 'private', {} )
        skey.update( { 'enc': enc, 'fmt': fmt, 'key': KeyStore.encrypt( passphrase + alias.encode(), key ) } )
        # Part of secure programming
        passphrase.zfill( len( passphrase ) )
        key.zfill( len( key ) )
        return True

    def getPrivateKey( self, alias:str, algo:str, passphrase: Union[str,bytes] ) -> Union[str,bytes,RSA._RSAPrivateKey]:
        """Retrieve the value of the private key from the keystore for the algorithm, this has a second level of decryption.

        :param alias:           Alias name of the private key to retrieve
        :param algo:            The algorithm that the key belong to
        :param passphrase:      The passphrase of the keystore or passphrase that belongs to the private key.
        :return:                returns the private key as UTF-8 string
        """
        if not self.__checkAsymmetricAlgorithm( algo ):
            return None

        obj = self.__data.setdefault( algo, {} ).setdefault( alias, {} ).get( 'private' )
        key = KeyStore.decrypt( passphrase + alias.encode(), obj[ 'key' ] )
        fmt = obj[ 'fmt' ]
        if fmt == 'PEM':
            if obj[ 'enc' ] == 'bytes':
                key = bytes( key )

        elif fmt == 'RSA._RSAPrivateKey':
            key = serialization.load_pem_private_key( key.encode('utf-8'), None )

        # Part of secure programming
        passphrase.zfill( len( passphrase ) )
        return key

    def hasPublicKey( self, alias:str, algo:str = 'RSA' ) -> bool:
        """Check a public key exists in the keystore for the algorithm.

        :param alias:           Alias name of the public to check
        :param algo:            The algorithm that the key belong to
        :return:
        """
        if not self.__checkAsymmetricAlgorithm( algo ):
            return False

        return self.__data.setdefault( algo, {} ).setdefault( alias, {} ).get( 'public' ) != None

    def setPublicKey( self, alias:str, key = None, algo:str = 'RSA' ) -> bool:
        """Store a public key in the keystore for the algorithm.

        :param alias:           Alias name of the public key to store
        :param key:             The public key to store in the keystore
        :param algo:            The algorithm that the key belong to
        :return:
        """
        if not self.__checkAsymmetricAlgorithm( algo ):
            return False

        enc = 'utf-8'
        fmt = 'raw'
        if isinstance( key, str ):
            if key.startswith( '-----BEGIN ' ):
                fmt = 'PEM'

        elif isinstance( key, bytes ):
            if key.startswith( b'-----BEGIN ' ):
                enc = 'bytes'
                fmt = 'PEM'

        elif isinstance( key, RSA.RSAPublicKey ):
            key = key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            fmt = 'RSA.RSAPublicKey'

        else:
            raise InvalidParameter( 'key' )

        obj = self.__data.setdefault( algo, {} ).setdefault( alias, {} ).setdefault( 'public', {} )
        obj.update( { 'key': key, 'fmt': fmt, 'enc': enc } )
        return True

    def getPublicKey( self, alias:str, algo:str = 'RSA' ):
        """Retrieve a public key from the keystore for the algorithm.

        :param alias:           Alias name of the public key to retrieve
        :param algo:            The algorithm that the key belong to
        :return:
        """
        if not self.__checkAsymmetricAlgorithm( algo ):
            return None

        obj =  self.__data.setdefault( algo, {} ).setdefault( alias, {} ).get( 'public' )
        key = obj[ 'key' ]
        fmt = obj[ 'fmt' ]
        if fmt == 'PEM':
            if obj[ 'enc' ] == 'bytes':
                key = bytes( key )

        elif fmt == 'RSA.RSAPublicKey':
            key = serialization.load_pem_public_key( key.encode( 'utf-8' ) )

        return key

    def hasCertificate( self, alias:str, algo:str = 'RSA' ) -> bool:
        """Check a certicate exists in the keystore for the algorithm.

        :param alias:           Alias name of the certicate to check
        :param algo:            The algorithm that the certicate belong to
        :return:
        """
        if not self.__checkAsymmetricAlgorithm( algo ):
            return False

        return self.__data.setdefault( algo, {} ).setdefault( alias, {} ).get( 'cerificate' ) != None

    def setCertificate( self, alias:str, cert, algo:str = 'RSA' ) -> bool:
        """Store a certicate in the keystore for the algorithm.

        :param alias:           Alias name of the certicate to store
        :param cert:            The certicate to store in the keystore
        :param algo:            The algorithm that the certicate belong to
        :return:
        """
        if not self.__checkAsymmetricAlgorithm( algo ):
            return False

        enc = 'utf-8'
        fmt = 'raw'
        if isinstance( cert, str ):
            if cert.startswith( '-----BEGIN ' ):
                fmt = 'PEM'

        elif isinstance( cert, bytes ):
            if cert.startswith( b'-----BEGIN ' ):
                enc = 'bytes'
                fmt = 'PEM'

        else:
            raise InvalidParameter( 'key' )

        obj = self.__data.setdefault( algo, {} ).setdefault( alias, {} ).setdefault( 'cerificate', {} )
        obj.update( { 'certicate': cert, 'fmt': fmt, 'enc': enc } )
        return True

    def getCertificate( self, alias:str, algo:str = 'RSA' ) -> Union[bytes,None]:
        """Retrieve a certicate from the keystore for the algorithm.

        :param alias:           Alias name of the certicate to retrieve
        :param algo:            The algorithm that the certicate belong to
        :return:
        """
        if not self.__checkAsymmetricAlgorithm( algo ):
            return None

        obj = self.__data.setdefault( algo, {} ).setdefault( alias, {} ).get( 'cerificate' )
        certicate = obj[ 'certicate' ]
        if obj[ 'fmt' ] == 'PEM':
            if obj[ 'enc' ] == 'bytes':
                certicate = bytes( certicate )

        return certicate

    def __checkSymmetricAlgorithm( self, algo:str ):
        return algo in ( 'DES', 'AES', 'IDEA', 'BLOWFISH', 'RC4', 'RC5', 'RC6' )

    def hasEncriptioneKey( self, alias:str, algo:str ) -> bool:
        """Check an encryption key exists in the keystore for the algorithm.

        :param alias:           Alias name of the encryption key to check
        :param algo:            The algorithm that the key belong to
        :return:
        """
        if not self.__checkSymmetricAlgorithm( algo ):
            return False

        return self.__data.setdefault( algo, {} ).get( alias ) != None

    def setEncriptioneKey( self, alias:str, algo:str, key, passphrase: Union[str,bytes] ):
        """Store an encryption key in the keystore for the algorithm.

        :param alias:           Alias name of the encryption key to store
        :param algo:            The algorithm that the key belong to
        :param key:             The encryption key to store in the keystore
        :param passphrase:      The passphrase of the keystore or passphrase that belongs to the encryption key.
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


        enc = 'utf-8'
        fmt = 'raw'
        if isinstance( key, str ):
            pass

        elif isinstance( key, bytes ):
            enc = 'bytes'


        else:
            raise InvalidParameter( 'key' )

        obj = self.__data.setdefault( algo, {} ).setdefault( alias, {} )
        obj.update( { 'cihper': KeyStore.encrypt( passphrase + alias.encode(), key ), 'fmt': fmt, 'enc': enc } )
        # Part of secure programming
        passphrase.zfill( len( passphrase ) )
        key.zfill( len( key ) )
        return True

    def getEncriptioneKey( self, algo:str, alias:str, passphrase: Union[str,bytes] ) -> Union[None,bytes]:
        """Retrieve an encryption key from the keystore for the algorithm.

        :param algo:            The algorithm that the key belong to
        :param alias:           Alias name of the encryption key to retrieve
        :param passphrase:      The passphrase of the keystore or passphrase that belongs to the encryption key.
        :return:
        """
        if not self.__checkSymmetricAlgorithm( algo ):
            return None

        obj = self.__data.setdefault( algo, {} ).get( alias, {} )
        result = None
        if obj.get( 'cihper', None ) is not None:
            result = KeyStore.decrypt( passphrase + alias.encode(), obj[ 'cihper' ] )
            if obj[ 'enc' ] == 'bytes':
                result = result.encode( 'utf-8' )

        # Part of secure programming
        passphrase.zfill( len( passphrase ) )
        return result

    if DEFINE_TESTING:
        def dump( self ):
            print( json.dumps( self.__data, indent = 4 ) )
            return


