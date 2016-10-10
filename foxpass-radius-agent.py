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

import json
import logging
import requests
import socket
import traceback

import duo_client
from pyrad.packet import AuthPacket, AccessAccept, AccessReject

import agent_config

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

MAX_PACKET_SIZE = 8192

def auth_with_foxpass(username, password):
    data = {'username': username, 'password': password}
    headers = {'Authorization': 'Token %s' % agent_config.API_KEY }
    reply = requests.post(agent_config.API_SERVER + '/v1/authn/', data=json.dumps(data), headers=headers)
    data = reply.json()

    if not data:
        raise Exception("Unknown error")

    if not 'status' in data:
        raise Exception("Unknown error")

    if data['status'] == 'error':
        if data['message'] == 'Incorrect password':
            logger.info("Invalid password")
            return False

        raise Exception(data['message'])

    if 'status' in data and data['status'] == 'ok':
        return True

    return False


def two_factor(username):
    # if Duo is not configured, return success
    if not agent_config.DUO_API_HOST or \
       not agent_config.DUO_IKEY or \
       not agent_config.DUO_SKEY:
        return True

    auth_api = duo_client.Auth(
        ikey=agent_config.DUO_IKEY,
        skey=agent_config.DUO_SKEY,
        host=agent_config.DUO_API_HOST
    )

    response = auth_api.auth('push',
                             username=username,
                             device='auto',
                             async=False)

    # success returns:
    # {u'status': u'allow', u'status_msg': u'Success. Logging you in...', u'result': u'allow'}

    # deny returns:
    # {u'status': u'deny', u'status_msg': u'Login request denied.', u'result': u'deny'}
    if response and response['status'] == 'allow':
        return True

    logger.info("Duo failed")
    return False


def group_match(username):
    if not agent_config.REQUIRE_GROUPS:
        return True

    allowed_set = set(agent_config.REQUIRE_GROUPS)

    headers = {'Authorization': 'Token %s' % agent_config.API_KEY }
    reply = requests.get(agent_config.API_SERVER + '/v1/users/' + username + '/groups/', headers=headers)
    data = reply.json()

    groups = data['data']

    user_set = set()

    for group in groups:
        user_set.add(group['name'])

    # see if user is any of the allowed groups
    if user_set.intersection(allowed_set):
        return True

    logger.info("User is not in an allowed group.")
    return False


def process_request(data, address, secret):
    error_message = None

    pkt = AuthPacket(packet=data, secret=secret, dict={})
    reply_pkt = pkt.CreateReply()
    reply_pkt.code = AccessReject

    try:
        username = pkt.get(1)[0]
        try:
            password = pkt.PwDecrypt(pkt.get(2)[0])
        except UnicodeDecodeError:
            logger.error("Error decrypting password -- probably incorrect secret")
            reply_pkt.code = AccessReject
            return reply_pkt.ReplyPacket()

        auth_status = auth_with_foxpass(username, password) and group_match(username) and two_factor(username)

        if auth_status:
            logger.info('Successful auth')
            reply_pkt.code = AccessAccept
            return reply_pkt.ReplyPacket()

        logger.info('Authentication failed')
        error_message = 'Authentication failed'

    except Exception as e:
        logger.exception(e)
        error_message = 'Unknown error'

    if error_message:
        reply_pkt.AddAttribute(18, error_message)
    return reply_pkt.ReplyPacket()


def run_agent(port, secret):
    # create socket & establish verification url
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # start listening
    sock.bind(('127.0.0.1', port))

    logger.info("Listening on port %d" % (port,))

    while True:
        try:
            # read data
            data, address = sock.recvfrom(MAX_PACKET_SIZE)
            logger.info('received %d bytes from %s' % (len(data), address))
            response_data = process_request(data, address, secret)
            sock.sendto(response_data, address)
            logger.info('sent %d bytes to %s' % (len(response_data), address))
        except KeyboardInterrupt:
            return
        except Exception as e:
            traceback.print_exc()


if __name__ == '__main__':
    run_agent(agent_config.PORT, agent_config.RADIUS_SECRET)
