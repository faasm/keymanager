from flask import Flask, request
from flask_api import status
import os
import pymongo
import socket
import tinyec
from tinyec import registry, ec as ec2
import hashlib
from secrets import randbelow
from Crypto.Hash import CMAC
import struct
import requests
import json
from binascii import hexlify, unhexlify
from base64 import b64encode, b64decode
from hashlib import sha256
from Crypto.Random import get_random_bytes
from threading import Thread
from util.utils import *
from util.constants import *
from util.crypto import *
from util.types import *
from util.env import *

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

MASTER_SECRET = get_random_bytes(MASTER_SECRET_SIZE)
spid = bytes.fromhex("d77b162b3dc029f174a627cb73ececde")
db_client = pymongo.MongoClient(DEFAULT_MONGO_HOST, DEFAULT_MONGO_PORT, serverSelectionTimeoutMS=DEFAULT_MONGO_TIMEOUT)
app = Flask(__name__)
state_pendings = {} #TODO cleanup thread

class ClientThread(Thread):
    def __init__(self, ip, port, socket, sim, cert, key):
        Thread.__init__(self)
        self._ip = ip
        self._port = port
        self._socket = socket
        self._cert = cert
        self._key = key
        self._sim = sim
        print("Got new Connection.")
    def run(self):
        print("running client thread")
        curve = registry.get_curve('secp256r1')
        data = self._socket.recv(4)
        if int.from_bytes(bytes(data), byteorder='little', signed=False) != 0:
            print("ERROR") #TODO
        data = self._socket.recv(ctypes.sizeof(sgx_ra_msg1_t))
        print("data: %s" % data)
        msg1 = sgx_ra_msg1_t.from_buffer_copy(data)
        remote_public_x_buffer = bytes(msg1.g_a)[:PUBLIC_KEY_X_SIZE]
        remote_public_y_buffer = bytes(msg1.g_a)[PUBLIC_KEY_X_SIZE:]
        private_key_point = randbelow(curve.field.n)
        public_key_point = private_key_point * curve.g
        remote_public_key_x = int.from_bytes(remote_public_x_buffer, byteorder='little', signed=False)
        remote_public_key_y = int.from_bytes(remote_public_y_buffer, byteorder='little', signed=False)
        def compute_shared_secret(private_key_point, remote_public_key_x, remote_public_key_y):
            """ Calc Diffiehellman key and compute secret
            """
            remote_public_key_point = ec2.Point(curve, remote_public_key_x, remote_public_key_y)
            shared_point = private_key_point * remote_public_key_point
            shared_secret = shared_point.x.to_bytes(PUBLIC_KEY_X_SIZE, byteorder="little")
            return shared_secret
        shared_secret = compute_shared_secret(private_key_point, remote_public_key_x, remote_public_key_y)
        kdk = CMAC.new(bytes([0]*16), ciphermod=AES)
        kdk.update(shared_secret)
        smk = CMAC.new(kdk.digest(), ciphermod=AES)
        smk.update(b'\x01SMK\x00\x80\x00')
        public_key_x_buffer = public_key_point.x.to_bytes(PUBLIC_KEY_X_SIZE, byteorder="little")
        public_key_y_buffer = public_key_point.y.to_bytes(PUBLIC_KEY_Y_SIZE, byteorder="little")
        private_key = ec.derive_private_key(
            private_value=1111,
            curve=ec.SECP256R1(),
            backend=default_backend()
        )
        signature_algorithm = ec.ECDSA(hashes.SHA256())
        data = public_key_x_buffer + public_key_y_buffer + bytes(msg1.g_a)
        signature = private_key.sign(data, signature_algorithm)
        r, s = decode_dss_signature(signature)
        r = r.to_bytes(32, byteorder="little")
        s = s.to_bytes(32, byteorder="little")
        msg = public_key_x_buffer + public_key_y_buffer + spid + (1).to_bytes(2, byteorder='little') + (1).to_bytes(2, byteorder='little') + r + s
        mac = CMAC.new(smk.digest(), ciphermod=AES)
        mac.update(msg)
        msg = msg + mac.digest() + (0).to_bytes(4, byteorder='little')
        self._socket.send(msg)
        data = self._socket.recv(4096)
        quote_size = int(len(data) - 336) #size of msg3
        msg3 = sgx_ra_msg3_t_factory(quote_size).from_buffer_copy(data)
        if bytes(msg1.g_a) != bytes(msg3.g_a):
            pass #TODO error
        """mac = CMAC.new(smk.digest(), ciphermod=AES)
        mac.update(bytes(msg3.g_a))
        print(mac.digest()) #TODO
        print(bytes(msg3.mac)) #TODO"""
        quote = sgx_quote_t_factory(len(bytes(msg3.quote))).from_buffer_copy(bytes(msg3.quote))
        b64quote = b64encode(bytes(msg3.quote)).decode('utf8')
        mk = CMAC.new(kdk.digest(), ciphermod=AES)
        mk.update(b'\x01MK\x00\x80\x00')
        sk = CMAC.new(kdk.digest(), ciphermod=AES)
        sk.update(b'\x01SK\x00\x80\x00') #shared secret for com
        shared_secret = sk.digest()
        def request_ias(quote):
            """ Request the Intel Attestation Service to verify to quote
            """
            data = {'isvEnclaveQuote': quote}
            print(data)
            cert = (self._cert, self._key)
            headers = {'Content-Type': 'application/json'}
            r = requests.post(IAS_QUOTE_URL, cert=cert, json=data, headers=headers)
            if r.status_code != 200:
                self._socket.close()
                return False, None
            return (True, json.loads(r.text))
        if not self._sim:
            status, attestation_result = request_ias(b64quote)
            if not status:
                self._socket.close()
                return
            if attestation_result['isvEnclaveQuoteStatus'] != 'OK':
                print("Warning. isvEnclaveQuoteStatus is not ok.")
                if attestation_result['isvEnclaveQuoteStatus'] != 'GROUP_OUT_OF_DATE': #only for lazy deploy
                    self._socket.close()
                    return
        def is_valid_mrenclave(report_body):
            """ Verify mrenclave to ensure that the right runtime is loaded in enclave
            """
            raw = b64decode(report_body)[112 : 112 + 32] #mrenclave starts at 112 (size 32)
            m = sha256()
            m.update(raw)
            mrenclave_hash = m.hexdigest()
            result = db_client["faasm"]["config"].find_one({'mrenclave': mrenclave_hash})
            if not result:
                return True #TODO WARNING only for test
            return True
        if not self._sim:
            if not is_valid_mrenclave(attestation_result['isvEnclaveQuoteBody']):
                self._socket.close()
                return
        payload = sgx_wamr_msg_pkey_mkey_t_factory(0, 0, MASTER_SECRET)
        cipher, nonce, mac = encrypt_aes_gcm_128(payload, shared_secret)
        res = sgx_wamr_msg_t_factory(0, mac, nonce, len(cipher), cipher)
        self._socket.send(res)
        print("Attestation was successful.")
        while True:
            data = self._socket.recv(ctypes.sizeof(sgx_wamr_msg_t))
            if len(data) == 0:
                break
            msg = sgx_wamr_msg_t.from_buffer_copy(data)
            nonce = b64encode(bytes(msg.nonce))
            if db_client["faasm"]["nonces"].find_one({"value": nonce}):
                print("that's not a new nonce!")
                res_payload = build_error_buffer('Replay protection.\0')
                cipher, nonce, mac = encrypt_aes_gcm_128(res_payload, shared_secret)
                res = sgx_wamr_msg_t_factory(msg.msg_id, mac, nonce, len(cipher), cipher)
            else: 
                encrypted_payload_data = self._socket.recv(msg.payload_len)
                payload_data = decrypt_aes_gcm_128(encrypted_payload_data, bytes(msg.nonce), bytes(msg.mac), shared_secret)
                db_client["faasm"]["nonces"].insert_one({"value": nonce})
                msg_type = payload_data[1]
                if msg_type == MSG_TYPE_CALL:
                    print("call")
                    payload = sgx_wamr_msg_hash_sid_t.from_buffer_copy(payload_data)
                    session_id = bytes(payload.session_id).decode()
                    function_hash_digest = hexlify(bytes(payload.opcode_enc_hash)).decode('ascii')
                    nonce = b64encode(bytes(payload.nonce))
                    result = db_client["faasm"]["nonces"].find_one({"value": nonce})
                    if result:
                        print(result)
                        print("ERROR: replay protection")
                        res_payload = build_error_buffer(bytes(msg.nonce), 'Replay protection.\0')
                        cipher, nonce, mac = encrypt_aes_gcm_128(res_payload, shared_secret)
                        res = sgx_wamr_msg_t_factory(msg.msg_id, mac, nonce, len(cipher), cipher)
                    else:
                        db_client["faasm"]["nonces"].insert_one({"value": nonce})
                        result = db_client["faasm"]["session"].find_one({"sid": session_id, "hash": function_hash_digest})
                        if result:
                            payload_key = result['key'].encode()
                            res_payload = sgx_wamr_payload_key_factory(bytes(msg.nonce), 0, 0, payload_key)
                            cipher, nonce, mac = encrypt_aes_gcm_128(res_payload, shared_secret)
                            res = sgx_wamr_msg_t_factory(msg.msg_id, mac, nonce, len(cipher), cipher)
                        else:
                            print("ERROR: function and sid do not match")
                            res_payload = build_error_buffer(bytes(msg.nonce), 'Function and sid doesnt match.\0')
                            cipher, nonce, mac = encrypt_aes_gcm_128(res_payload, shared_secret)
                            res = sgx_wamr_msg_t_factory(msg.msg_id, mac, nonce, len(cipher), cipher)
                elif msg_type == MSG_TYPE_BIND:
                    print("load")
                    payload = sgx_wamr_msg_hash_fct_t_factory(msg.payload_len).from_buffer_copy(payload_data)
                    function_name=bytes(payload.fct_name).decode()
                    function_name=function_name[:len(function_name)-1] #truncate last byte
                    function_hash_digest = hexlify(bytes(payload.opcode_enc_hash)).decode('ascii')
                    result = db_client["faasm"]["function"].find_one({"name": function_name, "hash": function_hash_digest})
                    if result:
                        op_key = result['key'].encode()
                        policy = result['ccp'].encode()
                        res_payload = sgx_wamr_okey_policy_t_factory(bytes(msg.nonce), 0, 0, op_key, policy)
                        cipher, nonce, mac = encrypt_aes_gcm_128(res_payload, shared_secret)
                        res = sgx_wamr_msg_t_factory(msg.msg_id, mac, nonce, len(cipher), cipher)
                    else:
                        print("error: hash and function do not match")
                        res_payload = build_error_buffer(bytes(msg.nonce), 'Hash and function doesnt match.\0')
                        cipher, nonce, mac = encrypt_aes_gcm_128(res_payload, shared_secret)
                        res = sgx_wamr_msg_t_factory(msg.msg_id, mac, nonce, len(cipher), cipher)
                elif msg_type == MSG_TYPE_STATE_WRITE:
                    print("state write")
                    payload = sgx_wamr_msg_state_write_t_factory(msg.payload_len).from_buffer_copy(payload_data)
                    buffer_nonce_digest = hexlify(bytes(payload.buffer_nonce)).decode('ascii')
                    namespace, key = bytes(payload.data[:payload.name_length]).decode().split(':')
                    total_execution_stack = bytes(payload.data[payload.name_length:]).decode()
                    state_secret = get_random_bytes(AES_KEY_SIZE)
                    filter = {'namespace': namespace, 'key': key}
                    update = {'$set': {'secret' : hexlify(state_secret).decode('ascii'), 'buffer_nonce': buffer_nonce_digest, 'stack': total_execution_stack}}
                    state_pendings[namespace + ':' + key] = {'filter': filter, 'update': update}
                    res_payload = sgx_wamr_payload_key_factory(bytes(msg.nonce), 0, 2, state_secret)
                    cipher, nonce, mac = encrypt_aes_gcm_128(res_payload, shared_secret)
                    res = sgx_wamr_msg_t_factory(msg.msg_id, mac, nonce, len(cipher), cipher)
                elif msg_type == MSG_TYPE_STATE_READ:
                    print("state read")
                    payload = sgx_wamr_msg_state_read_t_factory(msg.payload_len).from_buffer_copy(payload_data)
                    namespace, key = bytes(payload.key).decode().split(':')
                    result = db_client["faasm"]["state"].find_one({"namespace": namespace, "key": key})
                    if result:
                        buffer_nonce = unhexlify(result['buffer_nonce'])
                        state_secret = unhexlify(result["secret"])
                        stack = result['stack'].encode()
                        res_payload = sgx_wamr_state_read_res_factory(bytes(msg.nonce), 0, 2, state_secret, buffer_nonce, stack)
                        cipher, nonce, mac = encrypt_aes_gcm_128(res_payload, shared_secret)
                        res = sgx_wamr_msg_t_factory(msg.msg_id, mac, nonce, len(cipher), cipher)
                    else:
                        res_payload = build_error_buffer(bytes(msg.nonce), 'State is not registered.\0')
                        cipher, nonce, mac = encrypt_aes_gcm_128(res_payload, shared_secret)
                        res = sgx_wamr_msg_t_factory(msg.msg_id, mac, nonce, len(cipher), cipher)
                elif msg_type == MSG_TYPE_NONCE:
                    print("request check")
                    payload = sgx_wamr_msg_nonce_offer_t.from_buffer_copy(payload_data)
                    nonce = b64encode(bytes(payload.nonce))
                    if db_client["faasm"]["nonces"].find_one({"value": nonce}):
                        res_payload = build_error_buffer(bytes(msg.nonce), 'Replay protection.\0')
                        cipher, nonce, mac = encrypt_aes_gcm_128(res_payload, shared_secret)
                        res = sgx_wamr_msg_t_factory(msg.msg_id, mac, nonce, len(cipher), cipher)
                    else:
                        db_client["faasm"]["nonces"].insert_one({"value": nonce})
                        res_payload = sgx_wamr_ack_t_factory(bytes(msg.nonce), 0, 0)
                        cipher, nonce, mac = encrypt_aes_gcm_128(res_payload, shared_secret)
                        res = sgx_wamr_msg_t_factory(msg.msg_id, mac, nonce, len(cipher), cipher)
                elif msg_type == MSG_TYPE_STATE_WRITE_ACK: #state write reply
                    print("state write reply")
                    payload = sgx_wamr_msg_state_read_t_factory(msg.payload_len).from_buffer_copy(payload_data)
                    namespace, key = bytes(payload.key).decode().split(':')
                    if namespace + ':' + key not in state_pendings:
                        res_payload = build_error_buffer(bytes(msg.nonce), 'State is not registered.\0')
                        cipher, nonce, mac = encrypt_aes_gcm_128(res_payload, shared_secret)
                        res = sgx_wamr_msg_t_factory(msg.msg_id, mac, nonce, len(cipher), cipher)
                    else: 
                        tmp = state_pendings[namespace + ':' + key]
                        result = db_client["faasm"]["state"].update_one(tmp['filter'], tmp['update'], upsert=True)
                        if result:
                            del state_pendings[namespace + ':' + key]
                            res_payload = sgx_wamr_ack_t_factory(bytes(msg.nonce), 0, 0)
                            cipher, nonce, mac = encrypt_aes_gcm_128(res_payload, shared_secret)
                            res = sgx_wamr_msg_t_factory(msg.msg_id, mac, nonce, len(cipher), cipher)
                        else:
                            res_payload = build_error_buffer(bytes(msg.nonce), 'DB Error.\0')
                            cipher, nonce, mac = encrypt_aes_gcm_128(res_payload, shared_secret)
                            res = sgx_wamr_msg_t_factory(msg.msg_id, mac, nonce, len(cipher), cipher)
                else:
                    print("Error, received unknown message!")
                    res_payload = build_error_buffer(bytes(msg.nonce), 'Error, received unknown message!.\0')
                    cipher, nonce, mac = encrypt_aes_gcm_128(res_payload, shared_secret)
                    res = sgx_wamr_msg_t_factory(msg.msg_id, mac, nonce, len(cipher), cipher)
                self._socket.send(res)
        self._socket.close()
@app.route('/api/v1/registry/register/<namespace>', methods=['POST'])
def register(namespace):
    payload = request.json
    if not payload:
        abort(status.HTTP_400_BAD_REQUEST)
    policy = ['function', 'hash', 'hash_', 'key', 'allowed-functions','ccp','verify', 'chain-verify']
    if not is_valid_payload(payload, policy):
        return 'Payload is invalid', status.HTTP_400_BAD_REQUEST
    filter = {'namespace': namespace, 'name': payload["function"]}
    update = {'$set': {'hash' : payload['hash'], 'hash_' : payload['hash_'],'key': payload['key'], 'allowed-functions': payload['allowed-functions'], 'ccp': payload['ccp'], 'verify': payload['verify'], 'chain-verify': payload['chain-verify']}}
    db_client['faasm']['function'].update_one(filter, update, upsert=True)
    print("registered function '{}' for user '{}' with hash '{}' and policy '{}'".format(payload["function"], namespace, payload["hash"], policy))
    return 'Registration was successful.', status.HTTP_200_OK
@app.route('/api/v1/registry/pre-request/<namespace>/<function>', methods=['POST'])
def prerequest(namespace, function):
    print("got pre-request for function {} for user {}".format(function, namespace))
    payload = request.json
    if not payload:
        abort(status.HTTP_400_BAD_REQUEST)
    policy = ['key']
    if not is_valid_payload(payload, policy):
        return 'Payload is invalid', status.HTTP_400_BAD_REQUEST
    result = db_client['faasm']['function'].find_one({'namespace': namespace, 'name': function})
    if not result:
        return 'Called function in unknown in called namespace.', status.HTTP_400_BAD_REQUEST
    hash = result["hash"]
    full_ccp = {function: result['verify']}
    full_chain = {function: result['chain-verify']}
    hash_list = {function: result['hash_']}
    stack = [result['allowed-functions']]
    if len(result['allowed-functions']) > 0:
        while len(stack) > 0:
            current = stack.pop(0) #bfs
            current = list(current.keys())[0]
            if current in full_ccp.keys():
                continue
            result = db_client['faasm']['function'].find_one({'namespace': namespace, 'name': current})
            if not result:
                return 'Policy is not complete', status.HTTP_400_BAD_REQUEST
            else:
                full_ccp[current] = result['verify']
                full_chain[current] = result['chain-verify']
                hash_list[current] = result['hash_']
            stack.extend(result['allowed-functions'])
    sid = get_random_string(SID_SIZE)
    response = {}
    response['sid'] = sid
    response['hash-list'] = hash_list
    response['verify'] = full_ccp
    response['chain-verify'] = full_chain
    print("adding to db: sid: {}, hash: {}, key: {}".format(sid, hash, payload['key']));
    db_client['faasm']['session'].insert_one({"sid": sid, "hash": hash, "key": payload['key']})
    return response
@app.route('/')
def index():
    return 'KeyManager for faasm', status.HTTP_200_OK
def main(sim):
    #test mongodb connection
    try:
        db_client.server_info()
    except pymongo.errors.ServerSelectionTimeoutError as e:
        print("error: could not connect to MongoDB")
        print(e)
        return

    ip = os.environ.get('KM_HOST')
    if ip is None:
        ip = DEFAULT_KM_HOST
    registry_port = os.environ.get('KM_REGISTRY_PORT')
    if registry_port is None:
        registry_port = DEFAULT_KM_REGISTRY_PORT
    else:
        registry_port = int(registry_port)
    guard_port = os.environ.get('KM_GUARD_PORT')
    if guard_port is None:
        guard_port = DEFAULT_KM_GUARD_PORT
    else:
        guard_port = int(guard_port)
    print('Starting guard on {}:{}'.format(ip, guard_port))
    cert = os.environ.get('IAS_CERT')
    key = os.environ.get('IAS_KEY')
    if not sim:
        cert = os.environ.get('IAS_CERT')
        key = os.environ.get('IAS_KEY')
        if cert is None or key is None:
            raise Exception("Error. Please set IAS Creds in HW mode.")
        if not os.path.exists(cert) or not os.path.exists(key):
            raise Exception("Error. IAS Creds not found.")
    print('Starting registry on {}:{}'.format(ip, registry_port))
    threads = []
    def flask_thread():
        app.run(host=ip, port=registry_port)
    flask_thread = Thread(target=flask_thread)
    flask_thread.start()
    threads.append(flask_thread)
    tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_server.bind((ip, guard_port))
    while True:
        tcp_server.listen(5)
        try:
            (client_socket, (ip,port)) = tcp_server.accept()
        except KeyboardInterrupt:
            break
        new_thread = ClientThread(ip, port, client_socket, sim, cert, key)
        new_thread.start()
        threads.append(new_thread)
    for t in threads:
        t.join()
    db_client.close()
