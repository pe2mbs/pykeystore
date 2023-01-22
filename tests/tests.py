import os
import json
import pykeystore
from datetime import datetime, timedelta
import unittest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
import cryptography.hazmat.backends.openssl.rsa as RSA


class TestKeystoreEx( unittest.TestCase ):
    KEYSTORE_TESTS_EX = 'data/keystore-ex.pyks'
    PASSPHRASE_TESTS_EX = 'data/.passphrase-ex'
    def setUp(self) -> None:
        keystore = TestKeystoreEx.KEYSTORE_TESTS_EX
        if os.path.exists( TestKeystoreEx.PASSPHRASE_TESTS_EX ):
            passphrase = pykeystore.load_password( TestKeystoreEx.PASSPHRASE_TESTS_EX )

        else:
            passphrase = pykeystore.create_password( TestKeystoreEx.PASSPHRASE_TESTS_EX, True )

        if os.path.exists( keystore ):
            self.__keystore = pykeystore.KeyStoreEx.load( keystore, passphrase )

        else:
            self.__keystore = pykeystore.KeyStoreEx.create( keystore, passphrase )

        return

    def tearDown(self) -> None:
        self.__keystore.save( TestKeystoreEx.KEYSTORE_TESTS_EX,
                              pykeystore.load_password( TestKeystoreEx.PASSPHRASE_TESTS_EX ) )
        del self.__keystore
        return

    def test_01_add_password( self ):
        self.__keystore.setPassword( 'pe2mbs', 'verysecret' )
        self.assertEqual( self.__keystore.getPassword( 'pe2mbs' ), 'verysecret' )
        return

    def test_02_add_password_and_2fa( self ):
        # 16/20
        self.__keystore.setPassword( 'pe2mbs-2fa', 'verysecret', '0123456789ABCDEF' )
        self.assertEqual( self.__keystore.get2fa( 'pe2mbs-2fa' ), '0123456789ABCDEF' )
        return

    def test_03_get_account( self ):
        account, password, twofa = self.__keystore.getAccount( 'pe2mbs' )
        self.assertEqual( 'pe2mbs', account )
        self.assertEqual( 'verysecret', password )
        self.assertEqual( None, twofa )
        return

    def test_04_get_account_2fa( self ):
        account, password, twofa = self.__keystore.getAccount( 'pe2mbs-2fa' )
        self.assertEqual( 'pe2mbs-2fa', account )
        self.assertEqual( 'verysecret', password )
        self.assertEqual( '0123456789ABCDEF', twofa )
        return

    def test_05_add_symmetric_key( self ):
        key = Fernet.generate_key()
        self.__keystore.setEncriptioneKey( 'my-key', 'AES', key )
        retrieved = self.__keystore.getEncriptioneKey( 'my-key', 'AES' )
        self.assertEqual( key, retrieved )
        return

    def test_06_add_asymmetric_private_key( self ):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        self.__keystore.setPrivateKey( 'my-rsa-keys', pem, 'RSA' )
        retrieved = self.__keystore.getPrivateKey( 'my-rsa-keys', 'RSA' )
        self.assertEqual( pem, retrieved )
        return

    def assertKeyEqual( self, left, right ):
        if isinstance( left, RSA.RSAPrivateKey ) and isinstance( right, RSA.RSAPrivateKey ):
            self.assertEqual( left.private_bytes(encoding=serialization.Encoding.PEM,
                                                        format=serialization.PrivateFormat.PKCS8,
                                                        encryption_algorithm=serialization.NoEncryption()),
                              right.private_bytes(encoding=serialization.Encoding.PEM,
                                                      format=serialization.PrivateFormat.PKCS8,
                                                      encryption_algorithm=serialization.NoEncryption()) )

        elif isinstance( left, RSA.RSAPublicKey ) and isinstance( right, RSA.RSAPublicKey ):
            self.assertEqual( left.public_bytes( encoding=serialization.Encoding.PEM,
                                                 format=serialization.PublicFormat.SubjectPublicKeyInfo ),
                              right.public_bytes( encoding=serialization.Encoding.PEM,
                                                  format=serialization.PublicFormat.SubjectPublicKeyInfo ) )

        else:
            raise Exception( "Invalid parameter, left/right must RSA.PrivateKey: {type(left)} / {type(right)}" )

        return

    def test_06_1_add_asymmetric_private_key( self ):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.__keystore.setPrivateKey( 'my-rsa-keys-internal', private_key, 'RSA' )
        retrieved = self.__keystore.getPrivateKey( 'my-rsa-keys-internal', 'RSA' )
        self.assertKeyEqual( private_key, retrieved )
        return

    def test_07_add_asymmetric_public_key( self ):
        ppem = self.__keystore.getPrivateKey( 'my-rsa-keys', 'RSA' )
        private_key = serialization.load_pem_private_key(
            ppem.encode(),
            password=None,
        )
        public_key = private_key.public_key()
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        self.__keystore.setPublicKey( 'my-rsa-keys', pem, 'RSA' )
        retrieved = self.__keystore.getPublicKey( 'my-rsa-keys', 'RSA' )
        self.assertEqual( pem, retrieved )
        return

    def test_07_1_add_asymmetric_public_key( self ):
        private_key = self.__keystore.getPrivateKey( 'my-rsa-keys-internal', 'RSA' )
        public_key = private_key.public_key()
        self.__keystore.setPublicKey( 'my-rsa-keys-internal', public_key, 'RSA' )
        retrieved = self.__keystore.getPublicKey( 'my-rsa-keys-internal', 'RSA' )
        self.assertKeyEqual( public_key, retrieved )
        return

    def test_08_add_asymmetric_certicate( self ):
        ppem = self.__keystore.getPrivateKey( 'my-rsa-keys', 'RSA' )
        private_key = serialization.load_pem_private_key(
            ppem.encode(),
            password = None,
        )
        subject = issuer = x509.Name( [ x509.NameAttribute( NameOID.COUNTRY_NAME, u"NL" ),
                                        x509.NameAttribute( NameOID.STATE_OR_PROVINCE_NAME, u"Flevoland" ),
                                        x509.NameAttribute( NameOID.LOCALITY_NAME, u"Almere" ),
                                        x509.NameAttribute( NameOID.ORGANIZATION_NAME, u"PE2MBS" ),
                                        x509.NameAttribute( NameOID.COMMON_NAME, u"CA" ) ] )
        dt = datetime.utcnow().replace( microsecond = 0 )
        root_cert = x509.CertificateBuilder().subject_name( subject ).issuer_name( issuer ).\
            public_key( private_key.public_key() ).serial_number( x509.random_serial_number() ).\
            not_valid_before( dt ).not_valid_after( dt + timedelta(days=3650) ).\
            sign( private_key, hashes.SHA256(), default_backend() )
        data = root_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        self.__keystore.setCertificate( 'my-rsa-keys-CA', data, 'RSA' )
        cert = x509.load_pem_x509_certificate( self.__keystore.getCertificate( 'my-rsa-keys-CA', 'RSA' ).encode('utf-8') )
        self.assertEqual( '<Name(C=NL,ST=Flevoland,L=Almere,O=PE2MBS,CN=CA)>', str( cert.subject ) )
        self.assertEqual( dt, cert.not_valid_before )
        self.assertEqual( dt + timedelta( days = 3650 ), cert.not_valid_after )
        return

    def test_99_dump( self ):
        self.__keystore.dump()
        return

if __name__ == '__main__':
    unittest.main( verbosity=2 )
