import os
from pykeystore import KeyStoreEx, create_password, load_password
import json
import sys
import getopt


def usage():
    print("""crkeystore.py Create/edit Python Keystore, version 1.0.0.
     
Syntax:
    python3 crkeystore.py [options] <arguments>
    
Options:
-v                          Verbose output
-h/--help                   This help information
-p/--passphrase <filename>  The passphrase file to use for this keystore.
                            When the file doesn't exists, its created with a new unqiue passphrase. 
                            When omitted default <home-folder>/.keystore.password
-k/--keystore <filename>    The keystore to use, when the keystore doesn't exists an empty keystore is created.
                            When omitted default 'keystore.pyks'

Arguments:
    show [ account <name> | private <algo> <alias> | public <algo> <alias> | certicate <algo> <alias> | cipher <algo> <alias> ] 

    add { account | private | public | certicate | cipher }


[]  optional 
{}  one of mandatory




""")


def main_process():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hp:k:v", ["help", "passphrase=", "keystore="])

    except getopt.GetoptError as err:
        # print help information and exit:
        print(err)  # will print something like "option -a not recognized"
        usage()
        sys.exit(2)

    verbose = False
    keystore_filename = 'keystore.pyks'
    passphrase_filename = os.path.join( os.path.join( os.path.expanduser( '~' ), '.keystore.password' ) )
    for o, a in opts:
        if o == "-v":
            verbose = True

        elif o in ("-h", "--help"):
            usage()
            sys.exit()

        elif o in ("-p", "--passphrase"):
            passphrase_filename = a

        elif o in ("-k", "--keystore"):
            keystore_filename = a

        else:
            assert False, "unhandled option"

    passphrase_filename = os.path.abspath( passphrase_filename )
    if os.path.exists( passphrase_filename ):
        passphrase = load_password( passphrase_filename )

    else:
        passphrase = create_password( passphrase_filename )

    keystore_filename = os.path.abspath( keystore_filename )
    if os.path.exists( keystore_filename ):
        keystore = KeyStoreEx.load( keystore_filename, passphrase )

    else:
        keystore = KeyStoreEx.create( keystore_filename, passphrase )

    if len( args ) == 0:
        keystore.dump()

    else:
        # get first
        arg = args.pop(0).lower()
        if arg == 'show':
            if len( args ):
                arg = args.pop(0).lower()
                if arg == 'account':
                    if len( args ) == 1:
                        account = keystore.getAccount( args.pop(0) )
                        print( account )

                    else:
                        print( "incorrect parameters" )
                        usage()
                        sys.exit()

                elif arg == 'private':
                    if len( args ) == 2:
                        algo = args.pop(0).upper()
                        print( keystore.getPrivateKey( args.pop(0), algo ) )

                    else:
                        print( "incorrect parameters" )
                        usage()
                        sys.exit()

                elif arg == 'public':
                    if len( args ) == 2:
                        algo = args.pop(0).upper()
                        print( keystore.getPublicKey( args.pop(0), algo ) )

                    else:
                        print( "incorrect parameters" )
                        usage()
                        sys.exit()

                elif arg == 'cerificate':
                    if len( args ) == 2:
                        algo = args.pop(0).upper()
                        print( keystore.getCertificate( args.pop(0), algo ) )

                    else:
                        print( "incorrect parameters" )
                        usage()
                        sys.exit()

                elif arg == 'cihper':
                    if len( args ) == 2:
                        algo = args.pop(0).upper()
                        print( keystore.getEncriptioneKey( args.pop(0), algo ) )

                    else:
                        print( "incorrect parameters" )
                        usage()
                        sys.exit()

                else:
                    keystore.dump()

            else:
                keystore.dump()

        elif arg == 'add':
            arg = args.pop(0).lower()
            if arg == 'account':
                username = input( "Enter account name          : " )
                passsword = input( "Enter account password      : " )
                two_fa = input( "Enter account 2FA (or enter): " )
                keystore.setPassword( username, passsword, two_fa )

            elif arg == 'private':
                alias = input(    "Enter ALIAS name      : " )
                algo = input(     "Enter algorithm       : " ).upper()
                filename = input( "Enter privatekey file : " )
                if os.path.exists( filename ):
                    with open( filename, 'rb' ) as stream:
                        data = stream.read()

                    keystore.setPrivateKey( alias, data, algo )

                else:
                    print( f"{filename} not found" )

            elif arg == 'public':
                alias = input(    "Enter ALIAS name      : " )
                algo = input(     "Enter algorithm       : " ).upper()
                filename = input( "Enter publickey file  : " )
                if os.path.exists( filename ):
                    with open( filename, 'rb' ) as stream:
                        data = stream.read()

                    keystore.setPublicKey( alias, data, algo )

                else:
                    print( f"{filename} not found" )

            elif arg == 'certificate':
                alias = input(    "Enter ALIAS name       : " )
                algo = input(     "Enter algorithm        : " ).upper()
                filename = input( "Enter certificate file : " )
                if os.path.exists( filename ):
                    with open( filename, 'rb' ) as stream:
                        data = stream.read()

                    keystore.setCertificate( alias, data, algo )

                else:
                    print( f"{filename} not found" )

            elif arg == 'cipher':
                alias = input(    "Enter ALIAS name       : " )
                algo = input(     "Enter algorithm        : " ).upper()
                filename = input( "Enter cipher file : " )
                if filename == "":
                    key = input(  "Enter hexadecimal key  : " ).upper()
                    data = key.encode( 'hex' )
                    keystore.setEncriptioneKey( alias, algo, data )

                else:
                    if os.path.exists( filename ):
                        with open( filename, 'rb' ) as stream:
                            data = stream.read()

                        keystore.setPrivateKey( alias, data, algo )

                    else:
                        print( f"{filename} not found" )

            else:
                usage()
                sys.exit()

        else:
            usage()
            sys.exit()

    return


def main():
    try:
        main_process()

    except Exception as exc:
        print( exc, file = sys.stderr )

    return


if __name__ == '__main__':
    main()
