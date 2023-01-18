# Python Keystore
This package provides a simple keystore, 

The keystore is available is three types 
* **Simple** need too supply the passphres for every secure opration
* **Exteneded** need only onetime supply the passphrase
* **Keyring** need to supply the keyring information one time, for every secure operation the passphrase is retrieved from the keyring.

All three classes have functions for account information, asymmetric keys and symmetric keys.

The keys are stored by there alias and algorithm.

There are two layers of encryption;
1.  The keystore it self.
2.  the passwords, secrets and keys.

Therefore when the keystore is loaded into memory the actual secure information is not in clear text, only the data structure it readable.

## Keystore class functions

### Simple
This atre the functions in the Keystore class

* classmethod create( filename: str, passphrase: Union[str,bytes] ) -> 'KeyStore'
* classmethod load( cls, filename: str, passphrase: Union[str,bytes] ) -> 'KeyStore'
* function save( self, filename:str, passphrase: Union[str,bytes,None] ) -> None
* function hasAccount( self, account: str ) -> bool:
* function setPassword( self, account: str, password: str, passphrase: Union[str,bytes], two_fa = None ) -> None
* function getPassword( self, account:str, passphrase: Union[str,bytes] ) -> bytes
* function get2fa( self, account:str, passphrase: Union[str,bytes] ) -> bytes
* function getAccount( self, account:str, passphrase: Union[str,bytes] ) -> tuple( account, password [, twofa ] )
* function hasPrivateKey( self, alias:str, algo:str = 'RSA' ) -> bool
* function setPrivateKey( self, alias:str, key, algo:str, passphrase: Union[str,bytes] ) -> bool
* function getPrivateKey( self, alias:str, algo:str, passphrase: Union[str,bytes] ) -> bytes
* function hasPublicKey( self, alias:str, algo:str = 'RSA' ) -> bool
* function setPublicKey( self, alias:str, key = None, algo:str = 'RSA' ) -> bool
* function getPublicKey( self, alias:str, algo:str = 'RSA' ) -> bytes
* function hasCertificate( self, alias:str, algo:str = 'RSA' ) -> bool
* function setCertificate( self, alias:str, cert, algo:str = 'RSA' ) -> bool
* function getCertificate( self, alias:str, algo:str = 'RSA' ) -> Union[bytes,None]
* function hasEncriptioneKey( self, alias:str, algo:str ) -> bool
* function setEncriptioneKey( self, alias:str, algo:str, key, passphrase: Union[str,bytes] ) -> None
* function getEncriptioneKey( self, algo:str, alias:str, passphrase: Union[str,bytes] ) -> bytes

### Extended
Most functions are the same as for the simple Keystore, the following functions differ;

* setPassword( self, account: str, password: str, two_fa = None ) -> None
* getPassword( self, account:str ) -> bytes
* get2fa( self, account:str ) -> bytes
* getAccount( self, account:str ) -> tuple
* setPrivateKey( self, alias:str, key, algo:str ) -> bool
* getPrivateKey( self, alias:str, algo:str ) -> bytes 
* setEncriptioneKey( self, alias:str, algo:str, key ) - None
* getEncriptioneKey( self, algo:str, alias: str ) -> bytes

### Keyring
Most functions are the same as for the extended/simple Keystore, the following functions differ;

* classmethod loadWithKeyring( filename, system_name, keyring_name ) -> 'KeyringKeystore'
* classmethod createWithKeyring( filename, system_name, keyring_name ) -> 'KeyringKeystore'
* saveWithKeyring( filename, system_name, keyring_name ) -> None


## Examples
### Simple
For the simple Keystore the passphrase needs to be supplied for every operation,  

    import pykeystore
    passphrase = pykeystore.create_password( '~/python-keystore-passphrase' )
    store = pykeystore.KeyStore.create( 'keystore.pykst', passphrase )
    store.setPassord( 'account@example.com', 'somepassword', passphrase, '2FA-secret' )

    password = store.getPassword( 'account@example.com', passphrase )
    twofa = store.get2fa( 'account@example.com', passphrase )

    info = store.getAccount( 'account@example.com', passphrase  )

    keystore.save( 'keystore.pykst', passphrase )

    pykeystore.KeyStore.load( 'keystore.pykst', passphrase )
    info = store.getAccount( 'account@example.com', passphrase  )


### Extended
For the exetended Keystore the passphrase needs to be supplied once, this is less secure as every thing is stored in memory at the same time.

    import pykeystore
    passphrase = pykeystore.create_password( '~/python-keystore-passphrase' )
    store = pykeystore.KeyStoreEx.create( 'keystore.pykst', passphrase )
    store.setPassord( 'account@example.com', 'somepassword', '2FA-secret' )
    
    keystore.save( 'keystore.pykst', passphrase )


### Keyring
For the keyring Keystore the system-name and username are supplied once, but the actual passphrase the retrieved seperatly for every operation.   

    import pykeystore
    
    store = pykeystore.KeyRingStore.create( 'keystore.pykst', 'systemname', 'account' )
    store.setPassord( 'account@example.com', 'somepassword', '2FA-secret' )
    
    keystore.save( 'keystore.pykst' )



