import logging
from cryptography.fernet import Fernet
FILE_MASTER_DEFAULT = 'master.password'
STORE_SECRET        = True


def create_password( filename = FILE_MASTER_DEFAULT, store_secret = STORE_SECRET ) -> bytes:
    """
        Creates a new password and stores the passphrase in a text file.
        It is better than allowing the user to create the password:
            https://stackoverflow.com/a/55147077/3488853
        Args:
            filename:       name of the file where to store the master password
            store_secret:   if true store the secret in a file

        Returns:
            master password
    """
    # Create a new key and transform it to string
    key = Fernet.generate_key()
    logging.getLogger('pykeystore.password').warning( "Key generated. Remember to store it in a secure place." )
    if store_secret:
        with open( filename, "wb" ) as file:
            file.write( key )

        logging.getLogger('pykeystore.password').warning( f"Key stored in {filename}. Remember to gitignore this file!" )

    return key


def load_password( filename ) -> bytes:
    """Load the centrol stored the passphrase for the keystore.

    :param filename:        name of the file where to store the master password
    :return:
    """
    with open( filename, "rb" ) as file:
        passphrase = file.read()

    return passphrase
