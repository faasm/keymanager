import ctypes
from util.constants import MAC_SIZE, NONCE_SIZE, PUBLIC_KEY_SIZE, HASH_SIZE, SID_SIZE, AES_KEY_SIZE

MSG_TYPE_CALL = 0x0
MSG_TYPE_BIND = 0x1
MSG_TYPE_STATE_WRITE = 0x2
MSG_TYPE_STATE_READ = 0x3
MSG_TYPE_NONCE = 0x4
MSG_TYPE_STATE_WRITE_ACK = 0x5

def sgx_quote_t_factory(size):
    class sgx_quote_t(ctypes.Structure):
        _pack_ = 1
        _fields_ = [("version", 2 * ctypes.c_int8),
                ("sign_type", 2 * ctypes.c_int8),
                ("epid_group_id", 4 * ctypes.c_int8),
                ("qe_svn", 2 * ctypes.c_int8),
                ("pce_svn", 2 * ctypes.c_int8),
                ("xeid", 4 * ctypes.c_int8),
                ("basename", 32 * ctypes.c_int8),
                ("report_body",  384 * ctypes.c_int8),
                ("signature_len", 4 * ctypes.c_int8),
                ("signature", (2+2+4+2+2+5+32+384+4)* ctypes.c_int8)]
    return sgx_quote_t
class sgx_ra_msg1_t(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("g_a", PUBLIC_KEY_SIZE * ctypes.c_int8),
            ("gid", 4 * ctypes.c_int8)]
def sgx_ra_msg3_t_factory(quote_size):
    class sgx_ra_msg3_t(ctypes.Structure):
        _pack_ = 1
        _fields_ = [("mac", MAC_SIZE * ctypes.c_int8),
                ("g_a", PUBLIC_KEY_SIZE * ctypes.c_int8),
                ("ps_sec_prop", 256 * ctypes.c_int8),
                ("quote", quote_size * ctypes.c_int8)]
    return sgx_ra_msg3_t
class sgx_wamr_msg_t(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("msg_id", ctypes.c_ubyte),
            ("mac", MAC_SIZE * ctypes.c_int8),
            ('nonce', NONCE_SIZE * ctypes.c_int8),
            ('payload_len', ctypes.c_int32)]
def sgx_wamr_msg_state_read_t_factory(msg_len):
    class sgx_wamr_msg_state_read_t(ctypes.Structure):
        _pack_ = 1
        _fields_ = [("state", ctypes.c_int8)
                ("type", ctypes.c_int8),
                ("key", (msg_len - 1) * ctypes.c_int8)]
    return sgx_wamr_msg_state_read_t
def sgx_wamr_msg_state_write_t_factory(msg_len):
    class sgx_wamr_msg_state_write_t(ctypes.Structure):
        _pack_ = 1
        _fields_ = [("state", ctypes.c_int8),
                ("type", ctypes.c_int8),
                ("buffer_nonce", NONCE_SIZE * ctypes.c_int8),
                ("name_length", ctypes.c_int32),
                ("data", (msg_len - NONCE_SIZE - 5) * ctypes.c_int8)]
    return sgx_wamr_msg_state_write_t
def sgx_wamr_msg_pkey_quote_t_factory(msg_len):
    class sgx_wamr_msg_pkey_quote_t(ctypes.Structure):
        _pack_ = 1
        _fields_ = [("state", ctypes.c_int8),
                ("type", ctypes.c_int8),
                ("public_key", PUBLIC_KEY_SIZE * ctypes.c_int8),
                ("quote", (msg_len - PUBLIC_KEY_SIZE - 1) * ctypes.c_int8)]
    return sgx_wamr_msg_pkey_quote_t
def sgx_wamr_msg_hash_fct_t_factory(msg_len):
    class sgx_wamr_msg_hash_fct_t(ctypes.Structure):
        _pack_ = 1
        _fields_ = [("state", ctypes.c_int8),
                ("type", ctypes.c_int8),
                ("opcode_enc_hash", HASH_SIZE * ctypes.c_int8),
                ("fct_name", (msg_len - HASH_SIZE - 2)* ctypes.c_int8)]
    return sgx_wamr_msg_hash_fct_t
class sgx_wamr_msg_hash_sid_t(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("state", ctypes.c_int8),
                ("type", ctypes.c_int8),
                ("opcode_enc_hash", HASH_SIZE * ctypes.c_int8),
                ("session_id", SID_SIZE * ctypes.c_int8),
                ("nonce", NONCE_SIZE * ctypes.c_int8)]
class sgx_wamr_msg_pkey_mkey_t(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("enclave_master_key", AES_KEY_SIZE * ctypes.c_int8)]
class sgx_wamr_msg_nonce_offer_t(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("nonce", NONCE_SIZE * ctypes.c_int8)]
def sgx_wamr_msg_t_factory(msg_id, mac, nonce, payload_len, payload):
    if isinstance(msg_id, int):
        msg_id = msg_id.to_bytes(1, byteorder='big')
    if isinstance(payload_len, int):
        payload_len = payload_len.to_bytes(4, byteorder='little')
    return msg_id + mac + nonce + payload_len + payload

def to_byte(input_):
    return input_.to_bytes(1, byteorder='big')
def sgx_wamr_okey_policy_t_factory(nonce, status, type_, opcode_key, policy):
    policy_len = len(policy).to_bytes(4, byteorder='little')
    return nonce + to_byte(status) + to_byte(type_) + opcode_key + nonce + policy_len + policy
def sgx_wamr_payload_key_factory(nonce, status, type_, payload_key):
    return nonce + to_byte(status) + to_byte(type_) + payload_key
def sgx_wamr_state_read_res_factory(nonce, status, type_, state_secret, buffer_nonce, stack):
    return nonce + to_byte(status) + to_byte(type_) + state_secret + buffer_nonce + stack
def build_error_buffer(nonce, msg):
    return nonce + to_byte(1) + to_byte(0) + str.encode(msg)
def sgx_wamr_msg_pkey_mkey_t_factory(status, type_, key):
    return to_byte(status) + to_byte(type_) + key
def sgx_wamr_ack_t_factory(nonce, status, type_):
    return nonce + to_byte(status) + to_byte(type_)
