from types import MethodType
from scapy.layers.eap import EAPOL
from scapy.layers.dot11 import *
from scapy.layers.l2 import LLC, SNAP
from scapy.fields import *
import random
import hmac, hashlib
import os

from fakeap import *
from fakeap.constants import *
from itertools import count
import pyaes


secret=os.getenv("SECRET")
PSK="turtle{%s}"%secret
rpyutils.set_debug_level(rpyutils.Level.DEBUG)

# Ripped from scapy-latest with fixes
class EAPOL_KEY(Packet):
    name = "EAPOL_KEY"
    fields_desc = [
        ByteEnumField("key_descriptor_type", 1, {1: "RC4", 2: "RSN"}),
        # Key Information
        BitField("reserved2", 0, 2),
        BitField("smk_message", 0, 1),
        BitField("encrypted_key_data", 0, 1),
        BitField("request", 0, 1),
        BitField("error", 0, 1),
        BitField("secure", 0, 1),
        BitField("has_key_mic", 1, 1),
        BitField("key_ack", 0, 1),
        BitField("install", 0, 1),
        BitField("key_index", 0, 2),
        BitEnumField("key_type", 0, 1, {0: "Group/SMK", 1: "Pairwise"}),
        BitEnumField("key_descriptor_type_version", 0, 3, {
            1: "HMAC-MD5+ARC4",
            2: "HMAC-SHA1-128+AES-128",
            3: "AES-128-CMAC+AES-128",
        }),
        #
        LenField("key_length", None, "H"),
        LongField("key_replay_counter", 0),
        XStrFixedLenField("key_nonce", b"\x00"*32, 32),
        XStrFixedLenField("key_iv", b"\x00"*16, 16),
        XStrFixedLenField("key_rsc", b"\x00"*8, 8),
        XStrFixedLenField("key_id", b"\x00"*8, 8),
        XStrFixedLenField("key_mic", b"\x00"*16, 16),  # XXX size can be 24
        LenField("wpa_key_length", None, "H"),
        ConditionalField(
          XStrLenField("key", b"\x00"*16,
                     length_from=lambda pkt: pkt.key_length),
          lambda pkt: pkt.wpa_key_length and pkt.wpa_key_length > 0)
    ]

    def extract_padding(self, s):
        return s[:self.key_length], s[self.key_length:]

    def hashret(self):
        return struct.pack("!B", self.type) + self.payload.hashret()

    def answers(self, other):
        if isinstance(other, EAPOL_KEY) and \
                other.descriptor_type == self.descriptor_type:
            return 1
        return 0

# /tests/hwsim/test_ap_psk.py#L1524
def aes_wrap(kek, plain):
    n = len(plain) // 8
    a = 0xa6a6a6a6a6a6a6a6
    enc = pyaes.AESModeOfOperationECB(kek).encrypt
    r = [plain[i * 8:(i + 1) * 8] for i in range(0, n)]
    for j in range(6):
        for i in range(1, n + 1):
            b = enc(struct.pack('>Q', a) + r[i - 1])
            a = struct.unpack('>Q', b[:8])[0] ^ (n * j + i)
            r[i - 1] =b[8:]
    return struct.pack('>Q', a) + b''.join(r)

def pad_key_data(plain):
    pad_len = len(plain) % 8
    if pad_len:
        pad_len = 8 - pad_len
        plain += b"\xdd"
        pad_len -= 1
        plain += pad_len * b"\0"
    return plain


def customPRF512(key, amac, smac, anonce, snonce):
    """Source https://stackoverflow.com/questions/12018920/"""
    A = b"Pairwise key expansion"
    B = b"".join(sorted([amac, smac]) + sorted([anonce, snonce]))
    num_bytes = 64
    R = b''
    for i in range((num_bytes * 8 + 159) // 160):
        R += hmac.new(key, A + chb(0x00) + B + chb(i), hashlib.sha1).digest()
    return R[:num_bytes]

def gen_gtk(self):
    self.gtk_full = b"turtle{everyone gets a shell :)}"
    self.GTK = self.gtk_full[:16]
    self.MIC_AP_TO_GROUP = self.gtk_full[16:24]
    self.group_IV = count()

def do_something(self, message_2): 
    sta = message_2.getlayer(Dot11).addr2
    # do not reply to ourselves :-)
    if sta == self.ap.mac:
      print(sta, self.ap.mac)
      return

    if not self.eapol_ready:
     return

    self.eapol_ready = False
    eapol_key = EAPOL_KEY(message_2.getlayer(EAPOL).payload.load)
    snonce = eapol_key.key_nonce
    bssid = self.ap.mac
    amac = bytes.fromhex(bssid.replace(':', ''))
    smac = bytes.fromhex(sta.replace(':', ''))

    self.PMK = PMK = hashlib.pbkdf2_hmac('sha1', PSK.encode(), self.ap.get_ssid().encode(), 4096, 32)
    self.PTK = PTK = customPRF512(PMK, amac, smac, self.ANONCE, snonce)
    self.KCK = PTK[:16]
    self.KEK = PTK[16:32]
    self.TK  = PTK[32:48]
    self.MIC_AP_TO_STA = PTK[48:56]
    self.MIC_STA_TO_AP = PTK[56:64]
    self.client_iv = count()

    #from binascii import hexlify
    #print("PMK", hexlify(PMK))
    #print("PTK", hexlify(PTK))
    #print("amac", hexlify(amac))
    #print("smac", hexlify(smac))
    #print("anonce", hexlify(self.ANONCE), self.ANONCE)
    #print("snonce", hexlify(snonce))

    gen_gtk(self)

    self.KEY_IV = bytes([0 for i in range(16)])

    gtk_kde = b''.join([b'\xdd', chb(len(self.GTK)+6), b'\x00\x0f\xac', b'\x01', b'\x00\x00', self.GTK])
    plain = RSN + gtk_kde
    keydata = aes_wrap(self.KEK, pad_key_data(plain))

    ek = EAPOL(version='802.1X-2004',type='EAPOL-Key') \
         / EAPOL_KEY(key_descriptor_type=2, key_descriptor_type_version=2, install=1, key_type=1, key_ack=1,\
           has_key_mic=1, secure=1, encrypted_key_data=1, key_replay_counter=2, \
           key_nonce=self.ANONCE, key_mic=(b"\x00"*16), key_length=16, key=keydata, wpa_key_length=len(keydata))

    ek.key_mic = hmac.new(self.KCK, ek.build(), hashlib.sha1).digest()[:16]

    m3_packet = self.ap.get_radiotap_header() \
                / Dot11(subtype=0, FCfield='from-DS', addr1=sta, addr2=self.ap.mac, addr3=self.ap.mac, SC=self.ap.next_sc()) \
                / LLC(dsap=0xaa, ssap=0xaa, ctrl=3) \
                / SNAP(OUI=0, code=0x888e) \
                / ek

    print("SENDING M3 KEY")
    sendp(m3_packet, iface=self.ap.interface, verbose=False)

def create_message_1(self, sta):
    self.ANONCE = anonce = bytes([random.randrange(256) for i in range(32)])
    m1_packet = self.ap.get_radiotap_header() \
                / Dot11(subtype=0, FCfield='from-DS', addr1=sta, addr2=self.ap.mac, addr3=self.ap.mac, SC=self.ap.next_sc()) \
                / LLC(dsap=0xaa, ssap=0xaa, ctrl=3) \
                / SNAP(OUI=0, code=0x888e) \
                / EAPOL(version='802.1X-2004',type='EAPOL-Key') \
                / EAPOL_KEY(key_descriptor_type=2, key_descriptor_type_version=2, key_type=1, key_ack=1, has_key_mic=0, key_replay_counter=1, key_nonce=anonce, key_length=16)
    print("SENDING M1 KEY")
    self.eapol_ready = True
    sendp(m1_packet, iface=self.ap.interface, verbose=False)


def handle_assoc_resp(self, packet, sta, reassoc):
    self.sta = sta
    response_subtype = 0x01
    if reassoc == 0x02:
        response_subtype = 0x03

    assoc_packet = self.ap.get_radiotap_header() \
                   / Dot11(subtype=response_subtype, addr1=sta, addr2=self.ap.mac, addr3=self.ap.mac, SC=self.ap.next_sc()) \
                   / Dot11AssoResp(cap=0x3101, status=0, AID=self.ap.next_aid()) \
                   / Dot11Elt(ID='Rates', info=AP_RATES)

    print("Sending Association Response (0x01)...")
    sendp(assoc_packet, iface=self.ap.interface, verbose=False)
    create_message_1(self, sta)

def my_recv_pkt(self, packet):  # We override recv_pkt to include a trigger for our callback
    if EAPOL in packet:
        self.cb_do_something(packet)
    print(packet)
    self.recv_pkt(packet)

# iw dev wlan0 interface add mon0 type monitor
IFACE="mon0"
ap = FakeAccessPoint(IFACE, 'turtle1')
ap.wpa = AP_WLAN_TYPE_WPA2  # Enable WPA2
my_callbacks = Callbacks(ap)
my_callbacks.cb_recv_pkt = MethodType(my_recv_pkt, my_callbacks)
my_callbacks.cb_dot11_assoc_req = MethodType(handle_assoc_resp, my_callbacks)
my_callbacks.cb_do_something = MethodType(do_something, my_callbacks)
ap.callbacks = my_callbacks
ap.run()
