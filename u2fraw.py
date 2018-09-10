import collections
import os
import select
import sys
import time

import u2fcrypto


KGEN_KEY = None
HMAC_KEY = None
INCR_CNT = None
V2F_DIR = None

U2F_REGISTER        = 0x01
U2F_AUTHENTICATE    = 0x02
U2F_VERSION         = 0x03

SW_NO_ERROR                 = 0x9000
SW_CONDITIONS_NOT_SATISFIED = 0x6985
SW_WRONG_DATA               = 0x6984
SW_INS_NOT_SUPPORTED        = 0x6d00

ApduCmd = collections.namedtuple('ApduCmd', 'cla ins p1 p2 len data')


def initialize(device_master_secret_key, update_counter, v2f_dir):
    global KGEN_KEY
    global HMAC_KEY
    global INCR_CNT
    global V2F_DIR
    assert len(device_master_secret_key) == 64
    KGEN_KEY = device_master_secret_key[:32]
    HMAC_KEY = device_master_secret_key[32:]
    INCR_CNT = update_counter
    V2F_DIR = v2f_dir


def process_u2fraw_request(raw_request):
    try:
        apducmd = decode_apdu_command(raw_request)

        if apducmd.ins == U2F_VERSION:
            assert len(apducmd.data) == 0
            sw, resp = generate_get_version_response_message()
        elif apducmd.ins == U2F_REGISTER:
            assert len(apducmd.data) == 64
            application_parameter = apducmd.data[32:]
            challenge_parameter = apducmd.data[:32]
            sw, resp = generate_registration_response_message(application_parameter, challenge_parameter)
        elif apducmd.ins == U2F_AUTHENTICATE and apducmd.p1 == 0x07:
            assert len(apducmd.data) >= 65
            assert len(apducmd.data[65:]) == apducmd.data[64]
            sw, resp = generate_key_handle_checking_response(apducmd.data[32:64], apducmd.data[65:])
        elif apducmd.ins == U2F_AUTHENTICATE and apducmd.p1 == 0x03:
            assert len(apducmd.data) >= 65
            assert len(apducmd.data[65:]) == apducmd.data[64]
            sw, resp = generate_authentication_response_message(apducmd.data[32:64], apducmd.data[0:32], apducmd.data[65:])
        else:
            sw, resp = SW_INS_NOT_SUPPORTED, b''

    except AssertionError:
        sw, resp = SW_WRONG_DATA, b''

    return resp + sw.to_bytes(2, 'big')


def _is_good_key_handle(application_parameter, key_handle):
    try:
        assert len(key_handle) is 64
        kg_nonce = key_handle[:32]
        checksum = key_handle[32:]
        assert u2fcrypto.hmacsha256(HMAC_KEY, application_parameter + kg_nonce) == checksum
        return True
    except AssertionError:
        return False


def _get_key_pair(application_parameter, key_handle):
    kg_nonce = key_handle[:32]
    privatekey, publickey = u2fcrypto.generate_p256ecdsa_keypair(
            application_parameter + kg_nonce)
    return privatekey, publickey


def _generate_new_key_handle(application_parameter):
    kg_nonce = os.urandom(32)
    checksum = u2fcrypto.hmacsha256(HMAC_KEY, application_parameter + kg_nonce)
    key_handle = kg_nonce + checksum
    return key_handle


def generate_get_version_response_message():
    return SW_NO_ERROR, b'U2F_V2'


def generate_registration_response_message(application_parameter, challenge_parameter):
    print('''
%s %s

Got an event from some U2F relying party!

A website is asking you to register the U2F authenticator,
and it is claiming itself to be APPID with SHA256(APPID) =
%s''' % (sys.argv[0], V2F_DIR, application_parameter.hex()))
    if not user_says_yes('Enter yes to register'):
        return SW_CONDITIONS_NOT_SATISFIED, b''

    #print()
    #print('Please return to the web page in 3 seconds NOW!')
    #print()
    #time.sleep(3)

    kh = _generate_new_key_handle(application_parameter)
    sk, pk = _get_key_pair(application_parameter, kh)
    data_to_sign = b''.join([
        b'\x00',
        application_parameter,
        challenge_parameter,
        kh,
        pk,
    ])


    ATTESTATION_PRIVATE_KEY = bytes.fromhex('0b763f3769433f4054ef9b3fe00b53d78e8e2978e1241088891dd574cb6e570b')
    ATTESTATION_CERTIFICATE = bytes.fromhex('308201113081b8020100300906072a8648ce3d040130193117301506035504030c0e696e7465726d6564696174656361301e170d3138303931303035323635395a170d3138313130393035323635395a30123110300e06035504030c07753266746573743059301306072a8648ce3d020106082a8648ce3d030107034200048e080a5b8623b45a3263f1fc17fc134e84c4b1bd2928bda79f3e8f1e0526b58b6406c613b596e3aa04044738b21295b35e3aa5e44a4a250cd6f17c3f3b3fd876300906072a8648ce3d040103490030460221008c9eba2846d6be62b617526c3f2ce3e37bec36cc88a8d640e2d6544020795cd2022100c8e8f28dcf93f2963b506a661e52e8592771d12d930d2b6470c4f601223478a7')



    # attestation signature
    #signature = u2fcrypto.generate_sha256_p256ecdsa_signature(sk, data_to_sign)
    signature = u2fcrypto.generate_sha256_p256ecdsa_signature(ATTESTATION_PRIVATE_KEY, data_to_sign)
    result = b''.join([
        b'\x05',
        pk,
        b'\x40',
        kh,
        #u2fcrypto.x509encode_p256ecdsa_publickey(pk),
        (ATTESTATION_CERTIFICATE),
        signature,
    ])
    return SW_NO_ERROR, result


def generate_key_handle_checking_response(application_parameter, key_handle):
    if _is_good_key_handle(application_parameter, key_handle):
        return SW_CONDITIONS_NOT_SATISFIED, b''
    else:
        return SW_WRONG_DATA, b''


def generate_authentication_response_message(application_parameter, challenge_parameter, key_handle):
    if not _is_good_key_handle(application_parameter, key_handle):
        return SW_WRONG_DATA, b''

    print('''
%s %s

Got an event from some U2F relying party!

A website is asking you to login with the U2F authenticator,
and it is claiming itself to be APPID with SHA256(APPID) =
%s''' % (sys.argv[0], V2F_DIR, application_parameter.hex()))
    if not user_says_yes('Enter yes to login'):
        return SW_CONDITIONS_NOT_SATISFIED, b''
    print()

    sk, pk = _get_key_pair(application_parameter, key_handle)
    counter = INCR_CNT().to_bytes(4, 'big')
    data_to_sign = b''.join([
        application_parameter,
        b'\x01',
        counter,
        challenge_parameter,
    ])
    signature = u2fcrypto.generate_sha256_p256ecdsa_signature(sk, data_to_sign)
    result = b''.join([
        b'\x01',
        counter,
        signature
    ])
    return SW_NO_ERROR, result


def decode_apdu_command(x):
    assert len(x) >= 7
    cmd_data_len = (x[4]<<16)|(x[5]<<8)|x[6]
    data_and_tail = x[7:]
    assert len(data_and_tail) >= cmd_data_len
    return ApduCmd(cla=x[0], ins=x[1], p1=x[2], p2=x[3], len=cmd_data_len, data=data_and_tail[:cmd_data_len])


def user_says_yes(prompt, timeout=10):
    print('\n' + prompt + ': ', end='', flush=True)
    return ([] != select.select([sys.stdin], [], [], timeout)[0]) and sys.stdin.readline() == 'yes\n'
