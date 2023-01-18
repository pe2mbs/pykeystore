from pykeystore import KeyStore, KeystoreEx, KeyringKeystore, create_password



def test( ):
    ACCOUNT     = 'ps2mbs'
    PASSWORD    = '12345678'
    TWO_FA      = 'lasjkdlsdkjdakdskadklsdksladk'
    PK          = 'PK-TEST'
    PK_ALGO     = 'RSA'

    if os.path.exists( 'master.password' ):
        with open( 'master.password', 'r' ) as stream:
            passphrase = stream.read()

        ks = KeyStore.load( "keystore.pyks", passphrase )

    else:
        ks = KeyStore.create( "keystore.pyks", create_password() )


    ks.dump()
    if not ks.hasAccount( ACCOUNT ):
        ks.setPassword( ACCOUNT, PASSWORD, TWO_FA )

    if not ks.hasPrivateKey( PK, PK_ALGO ):
        ks.setPrivateKey( PK, PK_ALGO, 'keys' )
        ks.setPublicKey( PK, PK_ALGO, 'keys' )
        ks.setCertificate( PK, PK_ALGO, 'keys' )

    if not ks.hasEncriptioneKey( 'SIM', 'DES' ):
        ks.setEncriptioneKey( 'SIM', 'DES', 'keys' )

    if ks.getPassword( ACCOUNT ) == PASSWORD:
        print( ks.getPassword( ACCOUNT ) )

    else:
        print( "Password failed" )

    if ks.get2fa( ACCOUNT ) == TWO_FA:
        print( ks.get2fa( ACCOUNT ) )

    else:
        print( "2FA failed" )

    print( ks.getAccount( ACCOUNT ) )
    ks.dump()
    ks.save( "keystore.pyks" )



    return

if __name__ == "__main__":
    test()