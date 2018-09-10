import collections
import os
import struct
import time

import u2fraw


fd = None

U2FHID_REPORT_DESCRIPTOR = bytes([
    0x06, 0xd0, 0xf1,   # Usage Page (0xf1d0)
    0x09, 0x01,         # Usage (0x01)
    0xa1, 0x01,         # Collection (Application)
    0x09, 0x20,         #   Usage (FIDO Usage Data In)
    0x15, 0x00,         #     Logical Min (0)
    0x26, 0xff, 0x00,   #     Logical Max (255)
    0x75, 0x08,         #     Report Size (8)
    0x95, 0x40,         #     Report Count (64)
    0x81, 0x02,         #     Input (Data, Absolute, Variable)
    0x09, 0x21,         #   Usage (FIDO Usage Data Out)
    0x15, 0x00,         #     Logical Min (0)
    0x26, 0xff, 0x00,   #     Logical Max (255)
    0x75, 0x08,         #     Report Size (8)
    0x95, 0x40,         #     Report Count (64)
    0x91, 0x02,         #     Output (Data, Absolute, Variable)
    0xc0                # End Collection
])

# events to write to /dev/uhid
UHID_EVENT_FMT_CREATE2  = '< L 128s 64s 64s H H L L L L 4096s'
UHID_EVENT_FMT_INPUT2   = '< L H 4096s'

# events to read from /dev/uhid
UHID_EVENT_FMT_OUTPUT   = '< L 4096s H B'       # ev_type=6
UHID_EVENT_FMT_START    = '< L Q'               # ev_type=2
UHID_EVENT_FMT_OPEN     = '< L'                 # ev_type=4
UHID_EVENT_FMT_CLOSE    = '< L'                 # ev_type=5
UHID_EVENT_FMT_STOP     = '< L'                 # ev_type=3
UHID_EVENT_FMT_GETRPRT  = '< L L B B'           # ev_type=9
UHID_EVENT_FMT_SETRPRT  = '< L L B B H 4096s'   # ev_type=13


def get_randomness(n_bytes):
    return os.urandom(n_bytes)


def get_current_timestamp():
    return int(time.time() * 1000)


def uhid_process_event_from_kernel():
    ev = uhid_parse_event_from_kernel(os.read(fd, 4380))
    if ev[0] == 2:
        ev_type, dev_flags = ev
        print('/dev/uhid => UHID_START dev_flags=%d' % dev_flags)
    if ev[0] == 4:
        print('/dev/uhid => UHID_OPEN')
    if ev[0] == 5:
        print('/dev/uhid => UHID_CLOSE')
    if ev[0] == 3:
        print('/dev/uhid => UHID_STOP')
    if ev[0] == 9:
        ev_type, id_, rnum, rtype = ev
        print('/dev/uhid => UHID_GET_REPORT id=%d rnum=%d rtype=%d' % (id_, rnum, rtype))
    if ev[0] == 13:
        ev_type, id_, rnum, rtype, size, data = ev
        data = data[:size]
        print('/dev/uhid => UHID_SET_REPORT id=%d rnum=%d rtype=%d size=%d data=[%s]' % (id_, rnum, rtype, size, data.hex()))
    if ev[0] == 6:
        ev_type, data, size, rtype = ev
        data = data[:size]
        print('/dev/uhid => UHID_OUTPUT data=[%s] size=%d rtype=%d' % (data.hex(), size, rtype))
        _process_request_packet(data[1:])


def uhid_parse_event_from_kernel(event):
    assert len(event) == 4380
    ev_type = struct.unpack_from('< L', event)[0]
    if ev_type == 2:
        return struct.unpack_from(UHID_EVENT_FMT_START, event)
    elif ev_type == 6:
        return struct.unpack_from(UHID_EVENT_FMT_OUTPUT, event)
    elif ev_type == 4:
        return struct.unpack_from(UHID_EVENT_FMT_OPEN, event)
    elif ev_type == 5:
        return struct.unpack_from(UHID_EVENT_FMT_CLOSE, event)
    elif ev_type == 3:
        return struct.unpack_from(UHID_EVENT_FMT_STOP, event)
    elif ev_type == 9:
        return struct.unpack_from(UHID_EVENT_FMT_GETRPRT, event)
    elif ev_type == 13:
        return struct.unpack_from(UHID_EVENT_FMT_SETRPRT, event)
    else:
        raise ValueError('unknown UHID event type from kernel %d' % ev_type)


def uhid_generate_create2_event():
    ev_type = 11
    name = b''
    phys = b''
    uniq = b''
    rd_size = len(U2FHID_REPORT_DESCRIPTOR)
    bus = 6
    vendor = 0x0000
    product = 0x0000
    version = 0
    country = 0
    rd_data = U2FHID_REPORT_DESCRIPTOR

    buf = struct.pack(
        UHID_EVENT_FMT_CREATE2, ev_type, name, phys, uniq, rd_size, bus,
        vendor, product, version, country, rd_data
    )
    n = os.write(fd, buf)
    assert n == len(buf)

    print('/dev/uhid <= UHID_CREATE2 name=[%s] phys=[%s] uniq=[%s]'
        ' rd_size=%d bus=%d vendor=%d product=%d version=%d country=%d'
        ' rd_data=[%s]' % (
        name.hex(), phys.hex(), uniq.hex(), rd_size, bus,
        vendor, product, version, country, rd_data.hex()
    ))


def uhid_generate_input2_event(input_report_data):
    ev_type = 12
    size = len(input_report_data)
    data = input_report_data

    buf = struct.pack(UHID_EVENT_FMT_INPUT2, ev_type, size, data)
    n = os.write(fd, buf)
    assert n == len(buf)

    print('/dev/uhid <= UHID_INPUT2 size=%d data=[%s]' % (size, data.hex()))


U2FHID_PING  = 0x81
U2FHID_MSG   = 0x83
U2FHID_INIT  = 0x86
U2FHID_ERROR = 0xbf

INIT_PACKET_FMT = '> L B H 57s'
CONT_PACKET_FMT = '> L B 59s'

InitPacket = collections.namedtuple('InitPacket', 'cid cmd bcnt data')
ContPacket = collections.namedtuple('ContPacket', 'cid seq data')

ReqMsgStat = collections.namedtuple('ReqMsgStat', 'cid cmd bcnt data deadline')
ALREADY_EXPIRED_STATE = ReqMsgStat(0, 0, 0, b'', 0)
X = ALREADY_EXPIRED_STATE


def _process_request_packet(octets):
    assert len(octets) == 64
    if octets[4] >> 7:
        _process_request_initialization_packet(octets)
    else:
        _process_request_continuation_packet(octets)


ERR_INVALID_CMD     = b'\x01' # The command in the request is invalid
ERR_INVALID_PAR     = b'\x02' # The parameter(s) in the request is invalid
ERR_INVALID_LEN     = b'\x03' # The length field (BCNT) is invalid for the request
ERR_INVALID_SEQ     = b'\x04' # The sequence does not match expected value
ERR_MSG_TIMEOUT     = b'\x05' # The message has timed out
ERR_CHANNEL_BUSY    = b'\x06' # The device is busy for the requesting channel


def _process_request_initialization_packet(octets):
    global X

    initpkt = InitPacket(*struct.unpack(INIT_PACKET_FMT, octets))

    if initpkt.cmd not in (U2FHID_INIT, U2FHID_PING, U2FHID_MSG):
        _send_response_message(initpkt.cid, U2FHID_ERROR, ERR_INVALID_CMD)
        return

    assert (( initpkt.cmd == U2FHID_INIT and initpkt.cid == 0xffffffff and
              initpkt.bcnt == 8 ) or
            ( initpkt.cmd in (U2FHID_PING, U2FHID_MSG) and
              0 < initpkt.cid < 0xffffffff and initpkt.bcnt <= 7609 ))

    current_time = get_current_timestamp()

    if current_time < X.deadline:
        return # TODO respond a busy error
    elif initpkt.bcnt > 57:
        X = ReqMsgStat(
            initpkt.cid, initpkt.cmd, initpkt.bcnt, initpkt.data, current_time + 3000)
    elif initpkt.cmd == U2FHID_INIT:
        _process_request_message_INIT(initpkt.data[:initpkt.bcnt])
    elif initpkt.cmd == U2FHID_MSG:
        _process_request_message_MSG(initpkt.cid, initpkt.data[:initpkt.bcnt])
    elif initpkt.cmd == U2FHID_PING:
        _process_request_message_PING(initpkt.cid, initpkt.data[:initpkt.bcnt])


def _process_request_continuation_packet(octets):
    global X

    contpkt = ContPacket(*struct.unpack(CONT_PACKET_FMT, octets))
    assert 1 <= contpkt.cid <= 0xfffffffe and 0 <= contpkt.seq <= 127
    current_time = get_current_timestamp()

    if current_time >= X.deadline:
        return
    if contpkt.cid != X.cid:
        return
    if len(X.data) >= X.bcnt:
        return
    if contpkt.seq != ((len(X.data)-57)//59):
        return

    X = X._replace(data=X.data + contpkt.data)

    if len(X.data) >= X.bcnt:
        if X.cmd == U2FHID_MSG:
            _process_request_message_MSG(X.cid, X.data[:X.bcnt])
        if X.cmd == U2FHID_PING:
            _process_request_message_PING(X.cid, X.data[:X.bcnt])
        X = ALREADY_EXPIRED_STATE


def generate_new_channel_id():
    while True:
        r = get_randomness(4)
        i = int.from_bytes(r, 'big')
        if i != 0 and i != 0xffffffff:
            return i


def _process_request_message_INIT(nonce):
    #
    # response:
    #
    # cid = 0xffffffff
    # cmd = U2FHID_INIT (0x86)
    # payload =
    #
    #       8 bytes     provided nonce
    #       4 bytes     newly allocated channel id
    #       1 byte      U2FHID protocol version number (2)
    #       1 byte      device version number major (0)
    #       1 byte      device version number minor (0)
    #       1 byte      device version number build (0)
    #       1 byte      device capabilities flags (0)
    #
    print('U2FHID> got INIT request message cid=0xffffffff nonce=[%s]' % nonce.hex())
    new_cid = generate_new_channel_id()
    print('U2FHID> generate/allocate a new channel id: 0x%08x' % new_cid)
    payload = struct.pack('> 8s L B B B B B', nonce, new_cid, 2, 0, 0, 0, 0)
    _send_response_message(0xffffffff, U2FHID_INIT, payload)


def _process_request_message_PING(cid, data):
    print('U2FHID> got PING request message cid=0x%08x data=[%s]' % (cid, data.hex()))
    _send_response_message(cid, U2FHID_PING, data)


def _process_request_message_MSG(cid, data):
    print('U2FHID> got MSG request message cid=0x%08x data=[%s]' % (cid, data.hex()))

    resp = u2fraw.process_u2fraw_request(data)
    _send_response_message(cid, U2FHID_MSG, resp)


def _send_response_message(cid, cmd, payload):
    assert cmd in (U2FHID_INIT, U2FHID_PING, U2FHID_MSG, U2FHID_ERROR)
    assert len(payload) <= 7609

    print('U2FHID< send %s response message cid=0x%08x data=[%s]' % (
        {
            U2FHID_INIT  : 'INIT',
            U2FHID_PING  : 'PING',
            U2FHID_MSG   : 'MSG',
            U2FHID_ERROR : 'ERROR',
        }[cmd],
        cid,
        payload.hex()
    ))

    octets = struct.pack(INIT_PACKET_FMT, cid, cmd, len(payload), payload)
    payload = payload[57:]
    _sendout_response_packet(octets)

    for seq in range(128):
        time.sleep(0.25)
        if len(payload) == 0:
            break
        octets = struct.pack(CONT_PACKET_FMT, cid, seq, payload)
        payload = payload[59:]
        _sendout_response_packet(octets)


def _sendout_response_packet(octets):
    assert len(octets) == 64
    uhid_generate_input2_event(octets)


def run_uhid_event_loop():
    global fd
    fd = os.open('/dev/uhid', os.O_RDWR)
    uhid_generate_create2_event()
    while True:
        uhid_process_event_from_kernel()
