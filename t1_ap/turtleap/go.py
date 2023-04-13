
from types import MethodType
from scapy.layers.eap import EAPOL
from scapy.layers.dot11 import *
from scapy.layers.l2 import LLC, SNAP
from scapy.layers.dhcp import *
from scapy.fields import *
import random

import hmac, hashlib
import os

from fakeap import *
from fakeap.constants import *
from itertools import count
import pyaes
from salsa20 import Salsa20

# yep....
PSK=open("/dev/urandom","rb").read(16)

rpyutils.set_debug_level(rpyutils.Level.DEBUG)

IPS=[]
stations = {}

class Station:
    def __init__(self, mac):
        self.mac = mac

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
            0x20: "SALSA20-HMAC"
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
                     length_from=lambda pkt: pkt.wpa_key_length),
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

def pad_key_data(plain):
    pad_len = len(plain) % 64
    if pad_len:
        plain += b"\xdd" * (64  - pad_len)
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
    if sta == self.ap.mac:
      return

    if sta not in stations:
        return

    if not self.eapol_ready:
     return

    self.eapol_ready = False
    eapol_key = EAPOL_KEY(message_2.getlayer(EAPOL).payload.load)
    snonce = eapol_key.key_nonce
    bssid = self.ap.mac
    amac = bytes.fromhex(bssid.replace(':', ''))
    smac = bytes.fromhex(sta.replace(':', ''))

    stat = stations[sta]
    stat.PMK = PMK = hashlib.pbkdf2_hmac('sha1', PSK.encode(), self.ap.get_ssid().encode(), 4096, 32)
    stat.PTK = PTK = customPRF512(PMK, amac, smac, stat.ANONCE, snonce)
    stat.KCK = PTK[:16]
    stat.KEK = PTK[16:32]
    stat.TK  = PTK[32:48]
    stat.MIC_AP_TO_STA = PTK[48:56]
    stat.MIC_STA_TO_AP = PTK[56:64]
    stat.client_iv = count()

    #from binascii import hexlify
    #print("PMK", hexlify(PMK))
    #print("PTK", hexlify(PTK))
    #print("amac", hexlify(amac))
    #print("smac", hexlify(smac))
    #print("anonce", hexlify(self.ANONCE), self.ANONCE)
    #print("snonce", hexlify(snonce))

    if self.GTK == b"":
        gen_gtk(self)

    stat.KEY_IV = bytes([0 for i in range(16)])

    gtk_kde = b''.join([b'\xdd', chb(len(self.gtk_full)+6), b'\x00\x0f\xac', b'\x01', b'\x00\x00', self.gtk_full])
    plain = pad_key_data(RSN + gtk_kde)
    cipher = Salsa20(stat.KEK)
    keydata = cipher.encrypt(plain)

    ek = EAPOL(version='802.1X-2004',type='EAPOL-Key') \
         / EAPOL_KEY(key_descriptor_type=2, key_descriptor_type_version=2, install=1, key_type=1, key_ack=1,\
           has_key_mic=1, secure=1, encrypted_key_data=1, key_replay_counter=2, \
           key_nonce=stat.ANONCE, key_mic=(b"\x00"*16), key_length=16, key=keydata, wpa_key_length=len(keydata))

    ek.key_mic = hmac.new(stat.KCK, ek.build(), hashlib.sha1).digest()[:16]

    m3_packet = self.ap.get_radiotap_header() \
                / Dot11(subtype=0, FCfield='from-DS', addr1=sta, addr2=self.ap.mac, addr3=self.ap.mac, SC=self.ap.next_sc()) \
                / LLC(dsap=0xaa, ssap=0xaa, ctrl=3) \
                / SNAP(OUI=0, code=0x888e) \
                / ek

    print("SENDING M3 KEY")
    sendp(m3_packet, iface=self.ap.interface, verbose=False)
    stat.associated = True

    stations[sta] = stat

def create_message_1(self, sta):
    if sta not in stations:
        return
    stat = stations[sta]
    stat.ANONCE = anonce = bytes([random.randrange(256) for i in range(32)])
    m1_packet = self.ap.get_radiotap_header() \
                / Dot11(subtype=0, FCfield='from-DS', addr1=sta, addr2=self.ap.mac, addr3=self.ap.mac, SC=self.ap.next_sc()) \
                / LLC(dsap=0xaa, ssap=0xaa, ctrl=3) \
                / SNAP(OUI=0, code=0x888e) \
                / EAPOL(version='802.1X-2004',type='EAPOL-Key') \
                / EAPOL_KEY(key_descriptor_type=2, key_descriptor_type_version=2, key_type=1, key_ack=1, has_key_mic=0, key_replay_counter=1, key_nonce=anonce, key_length=16)
    print("SENDING M1 KEY")
    self.eapol_ready = True
    sendp(m1_packet, iface=self.ap.interface, verbose=False)
    stations[sta] = stat


def handle_assoc_resp(self, packet, sta, reassoc):

    if sta not in stations:
        stations[sta] = Station(sta)

    self.sta = sta
    response_subtype = 0x01
    if reassoc == 0x02:
        response_subtype = 0x03
    self.eapol_ready = True
    assoc_packet = self.ap.get_radiotap_header() \
                   / Dot11(subtype=response_subtype, addr1=sta, addr2=self.ap.mac, addr3=self.ap.mac, SC=self.ap.next_sc()) \
                   / Dot11AssoResp(cap=0x3101, status=0, AID=self.ap.next_aid()) \
                   / Dot11Elt(ID='Rates', info=AP_RATES)

    print("Sending Association Response (0x01)...")
    sendp(assoc_packet, iface=self.ap.interface, verbose=False)
    create_message_1(self, sta)

def ccmp_pn(pn):
  return pn.PN0 + (pn.PN1<<8) + (pn.PN2<<16) + (pn.PN3<<24)

def pn2bin(pn):
  return struct.pack(">Q", pn)

def decrypt(self, sta, packet):
  ccmp = packet[Dot11CCMP]
  pn = ccmp_pn(ccmp)

  aad_provided = ccmp.data[-16:]
  mic_key = b""
  if ccmp.key_id == 0:
      if sta not in stations:
          print("[-] Unknown station")
          return
      stat = stations[sta]
      key = stat.TK
      mic_key = stat.MIC_STA_TO_AP
  else:
      key = self.GTK
      mic_key = self.MIC_AP_TO_GROUP

  cipher = Salsa20(key, pn2bin(pn))
  data = cipher.decrypt(ccmp.data[:-16])
  aad_calc = hmac.new(mic_key, data, hashlib.sha1).digest()[:16]

  if aad_calc != aad_provided:
    print("*corrupt packet* dropping")
    return None

  return LLC() / SNAP() / Ether(data)


def encrypt(self, stat, packet, key_idx=1):
  data = packet.build()

  pn = 0
  aad_calc = b""
  key = b""

  if key_idx == 0:
      pn = next(stat.client_iv)
      aad_calc = hmac.new(stat.MIC_AP_TO_STA, data, hashlib.sha1).digest()[:16]
      key = stat.TK

  elif key_idx == 1:
      pn = next(self.group_IV)
      aad_calc = hmac.new(self.MIC_AP_TO_GROUP, data, hashlib.sha1).digest()[:16]
      key = self.GTK
  else:
      print("[-] unsupported key idx")
      return

  cipher = Salsa20(key, pn2bin(pn))
  payload = cipher.encrypt(data) + aad_calc

  pn0 = pn & 0xff
  pn1 = (pn>>8) & 0xff
  pn2 = (pn>>16) & 0xff
  pn3 = (pn>>24) & 0xff

  ccmp = Dot11CCMP(data=payload, ext_iv=1, key_id=key_idx, PN0 = pn0, PN1=pn1, PN2=pn2, PN3=pn3)
  return ccmp

def my_recv_pkt(self, packet):  # We override recv_pkt to include a trigger for our callback
    if EAPOL in packet:
      self.cb_do_something(packet)
    elif Dot11CCMP in packet:
      if packet[Dot11].FCfield == 'to-DS+protected':
          sta = packet[Dot11].addr2
          decrypted = decrypt(self, sta, packet)
          if decrypted:
              # make sure that the ethernet matches the station,
              # otherwise block
              if sta != decrypted[Ether].src:
                  print("[-] Invalid mac address for packet")
                  return
              handle_traffic(self, decrypted)
          return
    else:
        pass
        #packet.show()
    self.recv_pkt(packet)

def reply_dhcp_offer(self, incoming):
    # generate an IP
    if incoming.src not in IPS:
        IPS.append(incoming.src)
    dest_ip = "192.168.1.%d" % (1+len(IPS))

    for o in incoming[DHCP].options:
        # Log hostname for DNS revers lookup
        if o[0] == 'hostname':
            cmd = "echo %s %s.lan >> hostnames.txt" % (dest_ip, o[1].decode("ascii"))
            os.system(cmd )

    deth = incoming.src
    smac = bytes.fromhex(deth.replace(':', ''))
    broadcast = "192.168.1.255"
    gateway = server = "192.168.1.1"
    netmask = "255.255.255.0"

    packet = Ether(dst=deth, src=self.ap.mac, type=0x800) \
             / IP(dst=server, src="192.168.1.1") \
             / UDP(sport=67, dport=68) \
             / BOOTP(op=2, yiaddr=dest_ip, siaddr="192.168.1.1", chaddr=smac) \
             / DHCP(options=[("message-type", "offer"), ("server_id", server), ("broadcast_address", broadcast), ("router", gateway), ("subnet_mask", netmask)])
    print("send to", deth)
    enc_send(self, deth, packet)


def enc_send(self, sta, packet):
    if sta not in stations or not stations[sta].associated:
        print("[-] Invalid station")
        return

    packet =  self.ap.get_radiotap_header() \
                / Dot11(type='Data',  FCfield='from-DS+protected', addr1=sta, addr2=self.ap.mac, addr3=self.ap.mac, SC=self.ap.next_sc()) \
                / encrypt(self, stations[sta], packet)
    print("made-it")
    packet.show()
    sendp(packet, iface=self.ap.interface, verbose=False)


def handle_traffic(self, incoming):
    if DHCP in incoming:
        #handle a dhcp packet
        if incoming[UDP].dport == 67:
            if incoming[BOOTP].op == 1:
                reply_dhcp_offer(self, incoming)

# iw dev wlan0 interface add mon0 type monitor
IFACE="mon0"
ap = FakeAccessPoint(IFACE, 'turtle1')
ap.wpa = AP_WLAN_TYPE_WPA2  # Enable WPA2
my_callbacks = Callbacks(ap)
my_callbacks.cb_recv_pkt = MethodType(my_recv_pkt, my_callbacks)
my_callbacks.cb_dot11_assoc_req = MethodType(handle_assoc_resp, my_callbacks)
my_callbacks.cb_do_something = MethodType(do_something, my_callbacks)
ap.callbacks = my_callbacks
gen_gtk(my_callbacks)
ap.run()
