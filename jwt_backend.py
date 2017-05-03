import os
import sys
import jwt
import pam
import socket
import sqlite3
import getpass
import platform
from os.path import expanduser
from keyring.backend import KeyringBackend

ENCRYPTION_TYPE = 'HS512'
SECRET_KEY = socket.getfqdn().upper()
SQLITE_DB = "{0}/.jwtkeyring.db".format(expanduser("~"))


class JWTKeyring(KeyringBackend):
    """ Flatfile JWT encrypted keyring utilizing sql storage facility """

    def __init__(self):
        self.password = ''
        self.__non_sudo()
        try:
            self.__os_auth()
        except KeyboardInterrupt:
            print " -- Cancelled"
            sys.exit(1)

    def __os_auth(self):
        p = pam.pam()
        sys_info = self.__sys_details()
        pass_msg = ''' KeyChain password ({0}@{1} Auth): '''
        keyring_user = getpass.getuser()
        keyring_pass = getpass.getpass(pass_msg.format(keyring_user,
                                                       sys_info['hostname']))
        if not p.authenticate(keyring_user, keyring_pass):
            print "Authentication Error: {0} - {1}".format(p.code, p.reason)
            return False
        return True

    def __sys_details(self):
        return {'os': platform.system(),
                'hostname': socket.getfqdn(),
                'release': platform.release()}

    def __jwt_encode(self, dictionary):
        """ Converts presented dictionary into jwt token

        Args:
            dictionary (dict): Structure to be stored
        Returns:
            token (str): Encrypted jwt token with payload
        """
        return jwt.encode(dictionary, SECRET_KEY, algorithm=ENCRYPTION_TYPE)

    def __jwt_decode(self, token):
        """ Converts presented token into response dictionary

        Args:
            token (str): jwt token to be decrypted
        Returns:
            dictionary (dict): Stuctured response stored entry
        """
        return jwt.decode(token, SECRET_KEY, algorithms=[ENCRYPTION_TYPE])

    def __non_sudo(self):
        """ Ensures that the application user is not root """
        root_msg = ''' Cannot run this application as root '''
        if os.getuid() == 0:
            print root_msg
            sys.exit(2)

    def _connect(self):
        """ Creates database if it does not exist or connects """
        if not os.path.isfile(SQLITE_DB):
            conn = sqlite3.connect(SQLITE_DB)
            create = ''' CREATE TABLE IF NOT EXISTS `keystore`
                (id INTERGER AUTO INCREMENT PRIMARY KEY,
                 store_key CHAR(120) NOT NULL,
                 jwtoken TEXT,
                 timestamp DATETIME DEFAULT CURRENT_TIMESTAMP);
            '''
            conn.execute(create)
            conn.commit()
            conn.close()
        conn = sqlite3.connect(SQLITE_DB)
        return conn

    def _select(self, conn, service, username):
        """ Queries database for jwtoken to decypher

        Args:
            conn (obj): Connection object
            service (str): Service name category to store under
            username (str): Service username to be retrieved (key)
        Returns:
            password (str): Service password (value) of stored key
        """
        key = '{0}:{1}'.format(service, username)
        SELECT = ''' SELECT jwtoken FROM keystore WHERE store_key = ?; '''
        cur = conn.cursor()
        cur.execute(SELECT, [key])
        try:
            for row in cur.fetchall():
                token = row[0]
            return self.__jwt_decode(token)['password']
        except Exception as e:
            return None

    def _insert(self, conn, service, username, password):
        """ Inserts JWT token by key encrypted for storage

        Args:
            conn (obj): Connection object
            service (str): Service name category to store under
            username (str): Service username to be stored (key)
            password (str): Service password (key) to store encrypted
        Returns:
            No value returned
        """
        key = '{0}:{1}'.format(service, username)
        INSERT = ''' INSERT INTO keystore (store_key, jwtoken) VALUES (?, ?);
            '''
        token_setup = {'service': service,
                       'username': username,
                       'password': password}
        token = self.__jwt_encode(token_setup)
        conn.execute(INSERT, [key, token])
        conn.commit()

    def _delete(self, conn, service, username):
        """ Deletes JWT token associated with key

        Args:
            conn (obj): Connection object
            service (str): Service name category to store under
            username (str): Service username to delete entry with service
        Returns:
            No value returned
        """
        key = '{0}:{1}'.format(service, username)
        DELETE = ''' DELETE FROM keystore WHERE store_key = ?; '''
        conn.execute(DELETE, [key])
        conn.commit()

    def supported(self):
        """ Returns Supported (recommended)

        Taken from the docs:
            - 0 = Suitable
            - 1 = Recommended
            - -1 = Not Available
        """
        return 1

    def get_password(self, service, username):
        """ Retrieves the password from the jwtsqlite db

        Args:
            service (str): Service name category
            username (str): Service username (key)
        Returns:
            password (str): Service password (value)
        """
        conn = self._connect()
        self.password = self._select(conn, service, username)
        return self.password

    def set_password(self, service, username, password):
        """ Sets the password for the jwtsqlite db (key)=>(value)

        Args:
            service (str): Service name category
            username (str): Service username (key)
            password (str): Service password (value)
        Returns:
            0 (int): Response of 0
        """
        conn = self._connect()
        self._insert(conn, service, username, password)
        return 0

    def delete_password(self, service, username):
        """ Deletes the entry for the jwtsqlite db

        Args:
            service (str): Service name category
            username (str): Service username (key)
        Returns:
            None: No value returned
        """
        conn = self._connect()
        self._delete(conn, service, username)

if __name__ == '__main__':
    jwtk = JWTKeyring()
    service = 'fake'
    username = 'fake_username'
    password = 'fake_password'
    existing_password = jwtk.get_password(service, username)
    if not existing_password:
        jwtk.set_password(service, username, password)
    else:
        print existing_password
    if '--delete' in sys.argv:
        jwtk.delete_password(service, username)
