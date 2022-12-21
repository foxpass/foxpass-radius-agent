# Copyright (c) 2016-present, Foxpass, Inc.
# All rights reserved.
#
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# to test:
# radtest <user_name> <user_password> localhost:1812 1 <radius_secret>
#

from __future__ import print_function

# THIS NEEDS TO BE DONE FIRST (after __future__s)
# monkey patch for gevent
from gevent import monkey
monkey.patch_all()

import argparse
import io
import json
import logging
import requests
import socket
import time

from gevent.server import DatagramServer

import duo_client
from pyrad.packet import AuthPacket, AccessAccept, AccessReject
from pyrad.dictionary import Dictionary
from six.moves import configparser

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(levelname)-8s %(message)s')
logger = logging.getLogger(__name__)

MAX_PACKET_SIZE = 8192
DEFAULT_API_HOST = 'https://api.foxpass.com'

CONFIG = configparser.ConfigParser()

# make sure this data is of type 'unicode' in py2, not str.
# it's a no-op in py3
DICTIONARY_DATA = u"""
ATTRIBUTE       User-Name               1       string
ATTRIBUTE       Password                2       string
ATTRIBUTE       Reply-Message           18      string
"""


def get_config_item(name, default=None):
    section = 'default'

    if not CONFIG.has_option(section, name):
        return default

    return CONFIG.get(section, name)


def auth_with_foxpass(username, password):
    data = {'username': username, 'password': password}
    headers = {'Authorization': 'Token %s' % get_config_item('api_key')}
    url = get_config_item('api_host', DEFAULT_API_HOST) + '/v1/authn/'
    logger.info('API request to {}'.format(url))
    reply = requests.post(url, data=json.dumps(data), headers=headers)

    # raise exception if Foxpass returns an error other than 200 (success),
    # or 400 or 401 (both which will have a response in the json)
    if reply.status_code not in (200, 400, 401):
        reply.raise_for_status()

    data = reply.json()

    # format examples:
    # 200: {u'status': u'ok'}
    # 400: {u'status': u'error', u'message': u'Incorrect password'}

    if not data:
        raise Exception("Unknown error")

    if 'status' not in data:
        raise Exception("Unknown error")

    if data['status'] == 'error':
        if data['message'] == 'Incorrect password':
            logger.info("Invalid password")
            return False, None

        raise Exception(data['message'])

    if 'username' not in data:
        raise Exception("Unknown error")

    if data['status'] == 'ok':
        return True, data['username']

    return False, None


def two_factor(username, pkt_username, password=''):
    # get mfa type
    mfa_type = get_config_item('mfa_type')
    if mfa_type == 'okta':
        return okta_mfa(username, pkt_username)
    # backwards compatibility for clients with implicit duo config
    elif mfa_type == 'duo' \
        or (get_config_item('duo_api_host')
            or get_config_item('duo_ikey')
            or get_config_item('duo_skey')):
        return duo_mfa(username, password=password)

    # if MFA is not configured, return success
    logger.info("MFA not configured")
    return True


def duo_mfa(username, password=''):
    # if Duo is not configured, return success
    if not get_config_item('duo_api_host') or \
       not get_config_item('duo_ikey') or \
       not get_config_item('duo_skey'):
        logger.info("Duo not configured")
        return True

    auth_api = duo_client.Auth(
        ikey=get_config_item('duo_ikey'),
        skey=get_config_item('duo_skey'),
        host=get_config_item('duo_api_host')
    )

    duo_mode = get_config_item('duo_mode', 'push')

    # default mode is push only
    if duo_mode == 'push':
        response = auth_api.auth('push',
                                 username=username,
                                 device='auto',
                                 async_txn=False)
    # append mode appends factor to the end of password with comma separator
    elif duo_mode == 'append_mode':
        password, factor = duo_factor_split(password)
        if factor == 'push':
            response = auth_api.auth('push',
                                     username=username,
                                     device='auto',
                                     async_txn=False)
        # passcode factors are 6 digits
        elif len(factor) == 6 and factor.isdigit():
            response = auth_api.auth('passcode',
                                     username=username,
                                     passcode=factor,
                                     async_txn=False)
        else:
            logger.info("Invalid Duo factor")
            return False
    else:
        logger.info("Invalid Duo mode configured")
        return

    # success returns:
    # {u'status': u'allow', u'status_msg': u'Success. Logging you in...', u'result': u'allow'}

    # deny returns:
    # {u'status': u'deny', u'status_msg': u'Login request denied.', u'result': u'deny'}
    if response and response['result'] == 'allow':
        return True

    logger.info("Duo mfa failed")
    return False


def duo_factor_split(password):
    try:
        # split at comma once starting from right end of string
        password_elements = password.rsplit(',', 1)
        password, factor = password_elements[0], password_elements[1]
        return (password, factor)
    except IndexError:
        logger.info("Invalid comma split for Duo append mode factor")
        return (password, '')


def okta_mfa(username, pkt_username):
    # if Okta is not configured, return success
    if not get_config_item('okta_hostname') or \
       not get_config_item('okta_apikey'):
        logger.info("Okta MFA not configured")
        return True

    hostname = get_config_item('okta_hostname')
    api_key = get_config_item('okta_apikey')

    headers = {'Accept': 'application/json',
               'Authorization': 'SSWS %s' % api_key,
               'Content-Type': 'application/json',
               'User-Agent': 'FoxpassRadiusAgent/1.0'}

    # get the user id from okta
    url = "https://%s/api/v1/users/%s" % (hostname, username,)
    resp_json = okta_request(url, headers)

    if 'id' not in resp_json:
        logger.info("No Okta user found by foxpass username")

        # try again with the provided pkt username, may be email address
        url = "https://%s/api/v1/users/%s" % (hostname, pkt_username,)
        resp_json = okta_request(url, headers)

        if 'id' not in resp_json:
            logger.info("No Okta user found by pkt_username")
            return False

    okta_id = resp_json['id']

    # get the factors from okta, look for the push factor
    url = "https://%s/api/v1/users/%s/factors" % (hostname, okta_id,)
    resp_json = okta_request(url, headers)
    fid = None
    for factor in resp_json:
        if factor['provider'] == 'OKTA' and factor['factorType'] == 'push':
            url = factor['_links']['verify']['href']
            fid = factor['id']
            break

    if not fid:
        logger.info("No Okta push mfa set up")
        return False

    # start a new verify transaction
    resp_json = okta_request(url, headers, post=True)

    # poll for transaction completion
    while True:
        if resp_json['factorResult'] == 'SUCCESS':
            return True
        elif resp_json['factorResult'] == 'WAITING':
            url = resp_json['_links']['poll']['href']
            # sleep for 1 second to rate limit requests
            time.sleep(1.0)
            resp_json = okta_request(url, headers)
        else:
            break

    logger.info("Okta mfa failed")
    return False


def okta_request(url, headers, post=False):
    if post:
        r = requests.post(url, headers=headers, timeout=60)
    else:
        r = requests.get(url, headers=headers, timeout=60)
    r.raise_for_status()

    return json.loads(r.text)


def group_match(username):
    require_groups = get_config_item('require_groups')

    # if no groups were specified in the config, then allow access
    if not require_groups:
        return True

    allowed_set = set([name.strip() for name in require_groups.split(',')])

    headers = {'Authorization': 'Token %s' % get_config_item('api_key')}
    url = get_config_item('api_host', DEFAULT_API_HOST) + '/v1/users/' + username + '/groups/'
    logger.info('API request to {}'.format(url))
    reply = requests.get(url, headers=headers)
    data = reply.json()
    if not data:
        logger.info("No group data returned for user: %s" % (username))
        return False

    if 'data' not in data:
        logger.info("Unexpected response for user: %s - %s" % (username, data))
        return False

    groups = data['data']

    user_set = set()

    for group in groups:
        user_set.add(group['name'])

    # see if user is any of the allowed groups
    if user_set.intersection(allowed_set):
        return True

    logger.info("User %s is not in one of allowed groups (%s)." % (username, list(allowed_set)))
    return False


def process_request(data, address, secret):
    error_message = None

    pkt = AuthPacket(packet=data,
                     secret=secret,
                     dict=Dictionary(io.StringIO(DICTIONARY_DATA)))
    reply_pkt = pkt.CreateReply()
    reply_pkt.code = AccessReject

    try:
        # [0] is needed because pkt.get returns a list
        username = pkt.get('User-Name')
        if not username:
            logger.error("No User-Name in request")
            reply_pkt.code = AccessReject
            return reply_pkt.ReplyPacket()

        # attributes are returned as a list
        pkt_username = username[0]

        logger.info("Auth attempt for '%s'" % (pkt_username,))
        try:
            pkt_password = pkt.get('Password')
            if not pkt_password:
                logger.error("No password field in request")
                reply_pkt.code = AccessReject
                return reply_pkt.ReplyPacket()

            # [0] is needed because pkt.get returns a list
            pkt_password = pkt.PwDecrypt(pkt_password[0])
        except UnicodeDecodeError:
            logger.error("Error decrypting password -- probably incorrect secret")
            reply_pkt.code = AccessReject
            return reply_pkt.ReplyPacket()

        password = pkt_password
        if get_config_item('mfa_type') == 'duo':
            duo_mode = get_config_item('duo_mode', 'push')
            if duo_mode == 'append_mode':
                password, factor = duo_factor_split(pkt_password)

        (auth_status, username) = auth_with_foxpass(pkt_username, password)
        auth_status = auth_status and group_match(username) and two_factor(username, pkt_username, password=pkt_password)

        if auth_status:
            logger.info("Successful auth for '%s'" % (pkt_username,))
            reply_pkt.code = AccessAccept
            return reply_pkt.ReplyPacket()

        logger.info("Authentication failed for '%s'" % (pkt_username,))
        error_message = 'Authentication failed'

    except Exception as e:
        logger.exception(e)
        error_message = str(e)

    if error_message:
        reply_pkt.AddAttribute('Reply-Message', error_message)
    return reply_pkt.ReplyPacket()


class RADIUSServer(DatagramServer):
    def __init__(self, listener, secret):
        self.secret = secret
        super(RADIUSServer, self).__init__(listener)

    def handle(self, data, address):
        logger.info('received %d bytes from %s' % (len(data), address))
        response_data = process_request(data, address, self.secret)
        self.socket.sendto(response_data, address)
        logger.info('sent %d bytes to %s' % (len(response_data), address))


def run_agent(address, port, secret):
    # create socket & establish verification url
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # start listening
    sock.bind((address, port))

    logger.info("Listening on port %s:%d" % (address, port,))

    server = RADIUSServer(sock, secret)
    server.serve_forever()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', dest='config_file', help='Config file', default='/etc/foxpass-radius-agent.conf')
    args = parser.parse_args()

    CONFIG.read(args.config_file)

    secret = get_config_item('radius_secret')
    secret = secret.encode('utf-8')

    if not secret:
        logger.error("ERROR: radius_secret must be set in config file.")
        return

    if not get_config_item('api_key'):
        logger.error("ERROR: api_key must be set in config file.")
        return

    run_agent(get_config_item('address', '127.0.0.1'),
              int(get_config_item('port', 1812)),
              secret)


if __name__ == '__main__':
    main()
