# -*- coding: utf-8 -*-
'''
Saltstack Keystore implementation in Mysql, v 0.1

It relies on a flat table of minions for ease of use.

mysql> show create table minions\G
*************************** 1. row ***************************
       Table: minions
Create Table: CREATE TABLE `minions` (
  `minion_id` varchar(255) NOT NULL DEFAULT '',
  `minion_key` varchar(500) DEFAULT NULL,
  `key_type` enum('zmq','raet') DEFAULT NULL,
  `state` enum('acc','rej','den','pre') DEFAULT NULL,
  PRIMARY KEY (`minion_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1

It mimics the behaviour of salt.key.Key so it can be used as a drop-in
replacement for the filesystem store and to work seamlessly with salt-key.

Configuration and credentials for a keystore are configured in the master config:

'keystore': {
    'backend': 'mysql',
    'hostname': 'localhost',
    'username': 'root',
    'password': 'mysql',
    'database': 'keystore',
    'table': 'minions'
}
'''

import MySQLdb
import _mysql_exceptions as MySQLExceptions
from MySQLdb import FIELD_TYPE
import sys
import logging
from functools import wraps

# salt libraries
from salt.log import setup_console_logger
from salt.log.setup import logging as salt_logging
import salt.key
import salt.config
import salt.ext.six as six
from re import match as rematch

logger = salt_logging.getLogger(__name__)
log = logging.getLogger(__name__)

# TODO:
# implement dict_match()
# More safeguarding of mysql operations
# put more work into globbing -> PCRE in name_match()
# fire events like salt-key does

# We do not want to expose mysql-error to users unless
# enabled with debugging. This map translates SQL-errors
# into pretty error-messages.
error_map = {
    # Generic error
    0000: 'There was an error during a mysql-operation',
    # Duplicate primary key, minion already exists
    1062: 'Minion {0} already exists in database',
    # Syntax error in query
    1064: 'Failed to add minion, mysql reported a syntax error'
}

def compat(func):
    '''
    While long directory-names don't really matter, long strings
    in mysql are not pretty to work with. Therefore we map
    long directory-names to short states in Mysql. This decorator
    takes care of translating the dict-keys to the names salt
    expects to be returned from salt-key.
    '''

    @wraps(func)
    def wrapper(self, *args, **kwargs):

        d = func(self, *args, **kwargs)

        trans_map = {
            'acc': 'minions',
            'rej': 'minions_rejected',
            'pre': 'minions_pre',
            'den': 'minions_denied'
        }

        for key in trans_map:
            if key in d:
                d[trans_map[key]] = d.pop(key)
        return d
    return wrapper

class Mysql_key(salt.key.Key):

    # The four states a minion can be in
    ACC = 'acc'
    PEND = 'pre'
    REJ = 'rej'
    DEN = 'den'

    def __init__(self, **kwargs):
        '''
        Extract settings, setup the connection to the mysql server
        and configure automatic conversion to be done.
        '''

        setup_console_logger(
            log_level='info'
        )

        self.opts = kwargs
        self.store_opts = self.opts.get('keystore')

        # Not currently used, but might come in handy later
        # if for example a TIMESTAMP field is added to the table
        self.conversions = {
            FIELD_TYPE.LONG:int,
            FIELD_TYPE.TINY:int,
            FIELD_TYPE.TIMESTAMP:str
        }

        # Setup the mysql connection
        try:
            self.conn = MySQLdb.connect(
                host=self.store_opts['hostname'],
                user=self.store_opts['username'],
                passwd=self.store_opts['password'],
                db=self.store_opts['database'],
                conv=self.conversions
            )
        except MySQLExceptions.OperationalError as connect_err:
            log.error('Failed to connect to the mysql-Server: {0}'.format(connect_err))
            sys.exit(1)

        self.cursor = self.conn.cursor()

    def run_query(self, qry):
        '''
        Execute an MySQL-Query, catch possible errors and
        return data or error message.

        # We always return a tuple with two items:
        # Item 0 represents query success with True and False
        # Item 1 has data on success or an error message on failure
        '''

        try:
            log.debug(qry)
            self.cursor.execute(qry)
            self.conn.commit()
        except (
            MySQLdb.IntegrityError,
            MySQLdb.Error,
            MySQLdb.Warning,
            MySQLdb.ProgrammingError
        ) as sql_err:

            log.debug('Query failed: {0}'.format(sql_err))
            if sql_err[0] in error_map:
                return (False, error_map[sql_err[0]])
            else:
                return (False, error_map[0000])

        data = self.cursor.fetchall()
        return (True, data)

    def name_match(self, match, full=False):
        '''
        Returns a dict of minions matching with their state
        '''
        if full:
            matches = self.all_keys()
        else:
            matches = self.list_keys()

        ret_matched = {}

        # Rework the match to work with RE-matching. The globbing that
        # is usually done with '*' in salt.key.Key will not work here

        # If our match ends with an asterisk, accept
        # any number of characters of a-zA-Z0-9 instead
        if match.endswith('*'):
            match = match.strip('*')
            match += '\w*'


        if ',' in match and isinstance(match, str):
            match = match.split(',')

        for status, keys in six.iteritems(matches):

            for key in salt.utils.isorted(keys):
                if isinstance(match, list):
                    for match_item in match:
                        if rematch('^' + match + '$', key):
                            if status not in ret_matched:
                                ret_matched[status] = []
                            ret_matched[status].append(key)

                else:
                    if rematch('^' + match + '$', key):
                        if status not in ret_matched:
                            ret_matched[status] = []
                        ret_matched[status].append(key)
        return ret_matched

    def dict_match(self, match_dict):
        '''
        Accept a dictionary of keys and return the current state of the
        specified keys
        '''
        log.error('dict_match is not yet implemented')
        return {}

    def add_key(self, minion_id, minion_key, key_type, key_state='pre'):
        '''
        Insert a new minion into the MySQL-Keystore
        '''

        query = (
            "INSERT INTO {0} (minion_id, minion_key, key_type, state) "
            "VALUES ('{1}', '{2}', '{3}', '{4}');"
        )

        exec_query =  query.format(
            self.store_opts['table'],
            minion_id,
            minion_key,
            key_type,
            key_state
        )

        ret, data = self.run_query(exec_query)

        if ret:
            log.info('Minion {0} inserted into keystore'.format(minion_id))
            return data
        else:
#            log.info('FIX ME HERE ONCE FINISHED')
            raise AttributeError(data.format(minion_id))

    def list_keys(self):
        '''
        Return a dict of managed keys and what the key status are
        '''
        query = "SELECT minion_id, state FROM {0}"

        exec_query =  query.format(
            self.store_opts['table']
        )

        ret, data = self.run_query(exec_query)

        minions = {
            self.ACC: [],
            self.PEND: [],
            self.REJ: [],
            self.DEN: []
        }

        if ret:
            log.debug('Listing all Minions from keystore')

            # we run through a tuple of tuples with minion<->state mappings
            # (
            #     ('server01.mydomain.com', 'pre'),
            #     ('server02.mydomain.com', 'pre')
            # )
            for entry in data:
                try:
                    minions[entry[1]].append(entry[0])
                except KeyError:
                    minions[entry[1]] = []
                    minions[entry[1]].append(entry[0])

            return minions
        else:
            raise AttributeError(data)

    @compat
    def all_keys(self):
        '''
        Merge managed keys with local keys
        '''
        keys = self.list_keys()
        keys.update(self.local_keys())
        return keys

    @compat
    def list_status(self, match):
        '''
        Return a dict of managed keys under a named status
        '''

        query = "SELECT minion_id FROM {0} where state='{1}'"

        if match.startswith('acc'):
            minions = {'acc': []}
            query = "SELECT minion_id FROM {0} where state='{1}'".format(self.store_opts['table'], 'acc')
        elif match.startswith('pre') or match.startswith('un'):
            minions = {'pre': []}
            query = "SELECT minion_id FROM {0} where state='{1}'".format(self.store_opts['table'], 'pre')
        elif match.startswith('rej'):
            minions = {'rej': []}
            query = "SELECT minion_id FROM {0} where state='{1}'".format(self.store_opts['table'], 'rej')
        elif match.startswith('den'):
            minions = {'den': []}
            query = "SELECT minion_id FROM {0} where state='{1}'".format(self.store_opts['table'], 'den')
        elif match.startswith('all'):
            return self.all_keys()

        exec_query =  query.format(
            self.store_opts['table']
        )

        ret, data = self.run_query(exec_query)

        if ret:
            log.debug('Listing all Minions with status {0} from keystore'.format(match))

            # we run through a tuple of tuples with minion<->state mappings
            # (
            #     ('server01.mydomain.com'),
            #     ('server02.mydomain.com')
            # )
            minions[match] = [x[0] for x in data]
            return minions
        else:
            raise AttributeError(ret[1].format(match))

    @compat
    def accept(self, match=None, match_dict=None, include_rejected=False):
        '''
        Accept public keys. If "match" is passed, it is evaluated as a glob.
        Pre-gathered matches can also be passed via "match_dict".
        '''

        if match is not None:
            matches = self.name_match(match)
        elif match_dict is not None and isinstance(match_dict, dict):
            matches = match_dict
        else:
            matches = {}

        query = "UPDATE {0} SET state='{1}' WHERE minion_id='{2}' AND state='{3}'"

        # Update query if rejected minions should also be accepted
        if include_rejected:
            query += " OR state='{3}'"

        for state, minions in six.iteritems(matches):
            for minion in minions:
                if include_rejected:
                    exec_query = query.format(self.store_opts['table'], self.ACC, minion, self.PEND, self.REJ)
                else:
                    exec_query = query.format(self.store_opts['table'], self.ACC, minion, self.PEND)
                self.run_query(exec_query)
        return (
            self.name_match(match) if match is not None
            else self.dict_match(matches)
        )

    @compat
    def accept_all(self):
        '''
        Accept all keys in pre
        '''
        query = "UPDATE {0} set state='{1}' where minion_id='{2}'"
        data = self.list_keys()

        for key in data[self.PEND]:
            exec_query = query.format(self.store_opts['table'], self.ACC, key)
            self.run_query(exec_query)

        return self.list_keys()

    @compat
    def reject(self, match=None, match_dict=None, include_accepted=False):
        '''
        Reject public keys. If "match" is passed, it is evaluated as a glob.
        Pre-gathered matches can also be passed via "match_dict".
        '''
        if match is not None:
            matches = self.name_match(match)
        elif match_dict is not None and isinstance(match_dict, dict):
            matches = match_dict
        else:
            matches = {}

        query = "UPDATE {0} SET state='{1}' WHERE minion_id='{2}' AND state='{3}'"

        # Update query if accepted minions should also be rejected
        if include_accepted:
            query += " OR state='{3}'"

        for state, minions in six.iteritems(matches):
            for minion in minions:
                if include_accepted:
                    exec_query = query.format(self.store_opts['table'], self.REJ, minion, self.PEND, self.ACC)
                else:
                    exec_query = query.format(self.store_opts['table'], self.REJ, minion, self.ACC)
                self.run_query(exec_query)
        return (
            self.name_match(match) if match is not None
            else self.dict_match(matches)
        )

    @compat
    def reject_all(self):
        '''
        Reject all keys in pre
        '''
        query = "UPDATE {0} set state='{1}' where state='{2}' and minion_id='{3}'"
        data = self.list_keys()

        for key in data[self.PEND]:
            exec_query = query.format(self.store_opts['table'], self.REJ, self.PEND, key)
            self.run_query(exec_query)

        return self.list_keys()

    @compat
    def delete_key(self, match=None, match_dict=None, preserve_minions=False):
        '''
        Delete public keys. If "match" is passed, it is evaluated as a glob.
        Pre-gathered matches can also be passed via "match_dict".

        To preserve the master caches of minions who are matched, set preserve_minions
        '''
        query = "DELETE FROM {0} where minion_id='{1}'"
        if match is not None:
            matches = self.name_match(match)
        elif match_dict is not None and isinstance(match_dict, dict):
            matches = match_dict
        else:
            matches = {}

        ret = None

        for status, keys in six.iteritems(matches):
            for key in keys:
                ret, data = self.run_query(query.format(self.store_opts['table'], key))

        if ret:
            if self.opts.get('rotate_aes_key'):
                salt.crypt.dropfile(self.opts['cachedir'], self.opts['user'])
            return (
                self.name_match(match) if match is not None
                else self.dict_match(matches)
            )
        else:
            raise AttributeError

    @compat
    def delete_all(self):
        '''
        Delete all keys
        '''
        query = "DELETE FROM {0}".format(self.store_opts['table'])
        ret, data = self.run_query(query)

        if ret:
            if self.opts.get('rotate_aes_key'):
                salt.crypt.dropfile(self.opts['cachedir'], self.opts['user'])

            return self.list_keys()
        else:
            raise AttributeError(data)


    @compat
    def key_str(self, match):
        '''
        Return all managed key strings
        '''

        query = "SELECT minion_id, minion_key from {0} WHERE state='{1}'"

        minion_keys = {}

        for state, keys in six.iteritems(self.name_match(match)):
            minion_keys[state] = {}
            exec_query = query.format(self.store_opts['table'], state)
            ret, state_data = self.run_query(exec_query)

            for entry in state_data:
                minion_keys[state][entry[0]] = entry[1]

        return minion_keys

    @compat
    def key_str_all(self):
        '''
        Return all managed key strings
        '''

        query = "SELECT minion_id, minion_key from {0} WHERE state='{1}'"

        minion_keys = {}
        data = self.list_keys()

        for state in data:
            minion_keys[state] = {}
            exec_query = query.format(self.store_opts['table'], state)
            ret, state_data = self.run_query(exec_query)

            for entry in state_data:
                minion_keys[state][entry[0]] = entry[1]

        return minion_keys



if __name__ == '__main__':

    minion_pre = {
        'minion_id': 'minion_pre',
        'minion_key': ''.join(['-----BEGIN PUBLIC KEY-----',
                               'ABCDEFGH',
                               '-----END PUBLIC KEY-----']),
        'key_type': 'zmq'
    }

    minion_rej = {
        'minion_id': 'minion_rej',
        'minion_key': ''.join(['-----BEGIN PUBLIC KEY-----',
                               'IJKLMNOP',
                               '-----END PUBLIC KEY-----']),
        'key_type': 'zmq',
        'state': 'rej'
    }


    minion_acc1 = {
        'minion_id': 'minion',
        'minion_key': ''.join(['-----BEGIN PUBLIC KEY-----',
                               'QRSTUVWXY',
                               '-----END PUBLIC KEY-----']),
        'key_type': 'zmq',
        'state': 'acc'
    }

    minion_acc2 = {
        'minion_id': 'minion2',
        'minion_key': ''.join(['-----BEGIN PUBLIC KEY-----',
                               '123456789',
                               '-----END PUBLIC KEY-----']),
        'key_type': 'zmq',
        'state': 'acc'
    }

    kwargs = {
        'keystore': {
            'backend': 'mysql',
            'hostname': 'localhost',
            'username': 'root',
            'password': 'mysql',
            'database': 'keystore',
            'table': 'minions'
        }
    }

    opts = salt.config.master_config('/etc/salt/master')
    kwargs.update(opts)
    keystore = Mysql_key(**kwargs)

    try:
        keystore.add_key(
            minion_pre['minion_id'],
            minion_pre['minion_key'],
            minion_pre['key_type']
        )
        keystore.add_key(
            minion_rej['minion_id'],
            minion_rej['minion_key'],
            minion_rej['key_type'],
            minion_rej['state']
        )
        keystore.add_key(
            minion_acc1['minion_id'],
            minion_acc1['minion_key'],
            minion_acc1['key_type'],
            minion_acc1['state']
        )
        keystore.add_key(
            minion_acc2['minion_id'],
            minion_acc2['minion_key'],
            minion_acc2['key_type'],
            minion_acc2['state']
        )
    except AttributeError as add_err:
        log.error('Failed to add minion to keystore: {1}'.format(add_err))

    raw_input('\nEnter to continue / local_keys()')
    print keystore.local_keys()

    raw_input('\nEnter to continue / all_keys()')
    print keystore.all_keys()

    raw_input('\nEnter to continue / list_status("all")')
    print keystore.list_status('all')

    raw_input('\nEnter to continue / list_status("pre")')
    print keystore.list_status('pre')

    raw_input('\nEnter to continue / key_str("minion")')
    print keystore.key_str('minion')

    raw_input('\nEnter to continue / key_str_all()')
    print keystore.key_str_all()

    raw_input('\nEnter to continue / accept("minion_pre")')
    print keystore.accept('minion_pre')

    raw_input('\nEnter to continue / accept_all()')
    print keystore.accept_all()

    raw_input('\nEnter to continue / reject("minion_pre")')
    print keystore.reject('minion_pre')

    raw_input('\nEnter to continue / reject_all()')
    print keystore.reject_all()

    raw_input('\nEnter to continue / delete_key("minion_pre")')
    print keystore.delete_key('minion_pre')

    raw_input('\nEnter to continue / delete_all()')
    print keystore.delete_all()
