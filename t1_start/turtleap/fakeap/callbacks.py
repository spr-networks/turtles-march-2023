from .rpyutils import *
from .constants import *

from scapy.fields import *
from scapy.layers.eap import *
from scapy.layers.dot11 import *
from scapy.layers.dhcp import *
from scapy.layers.dns import DNS
from scapy.layers.inet import TCP, UDP

from scapy.layers.l2 import ARP

class Callbacks(object):
    def __init__(self, ap):
        self.ap = ap

        self.cb_recv_pkt = self.recv_pkt
        self.cb_dot11_probe_req = self.dot11_probe_resp
        self.cb_dot11_beacon = self.dot11_beacon
        self.cb_dot11_auth = self.dot11_auth
        self.cb_dot11_ack = self.dot11_ack
        self.cb_dot11_assoc_req = self.dot11_assoc_resp

    def recv_pkt(self, packet):
        try:
            if len(packet.notdecoded[8:9]) > 0:  # Driver sent radiotap header flags
                # This means it doesn't drop packets with a bad FCS itself
                flags = ord(packet.notdecoded[8:9])
                if flags & 64 != 0:  # BAD_FCS flag is set
                    # Print a warning if we haven't already discovered this MAC
                    if not packet.addr2 is None:
                        printd("Dropping corrupt packet from %s" % packet.addr2, Level.BLOAT)
                    # Drop this packet
                    return

            # Management
            if packet.type == DOT11_TYPE_MANAGEMENT:
                if packet.subtype == DOT11_SUBTYPE_PROBE_REQ:  # Probe request
                   if Dot11Elt in packet:
                        ssid = packet[Dot11Elt].info

                        printd("Probe request for SSID %s by MAC %s" % (ssid, packet.addr2), Level.DEBUG)

                        # Only send a probe response if one of our own SSIDs is probed
                        if ssid in self.ap.ssids or (Dot11Elt in packet and packet[Dot11Elt].len == 0):
                            if not (self.ap.hidden and ssid != self.ap.get_ssid()):
                                self.cb_dot11_probe_req(packet.addr2, self.ap.get_ssid())
                elif packet.subtype == DOT11_SUBTYPE_AUTH_REQ:  # Authentication
                    if packet.addr1 == self.ap.mac:  # We are the receivers
                        self.ap.sc = -1  # Reset sequence number
                        self.cb_dot11_auth(packet.addr2)
                elif packet.subtype == DOT11_SUBTYPE_ASSOC_REQ or packet.subtype == DOT11_SUBTYPE_REASSOC_REQ:
                    if packet.addr1 == self.ap.mac:
                        self.cb_dot11_assoc_req(packet, packet.addr2, packet.subtype)
        except Exception as err:
            print("Unknown error at monitor interface: %s" % repr(err))

    def dot11_probe_resp(self, source, ssid):
        probe_response_packet = self.ap.get_radiotap_header() \
                                / Dot11(subtype=5, addr1=source, addr2=self.ap.mac, addr3=self.ap.mac, SC=self.ap.next_sc()) \
                                / Dot11ProbeResp(timestamp=self.ap.current_timestamp(), beacon_interval=0x0064, cap=0x3101) \
                                / Dot11Elt(ID='SSID', info=ssid) \
                                / Dot11Elt(ID='Rates', info=AP_RATES) \
                                / Dot11Elt(ID='DSset', info=chr(self.ap.channel))

        # If we are an RSN network, add RSN data to response
        probe_response_packet = probe_response_packet / RSN

        sendp(probe_response_packet, iface=self.ap.interface, verbose=False)

    def dot11_beacon(self, ssid):
        # Create beacon packet
        beacon_packet = self.ap.get_radiotap_header() \
                     / Dot11(subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=self.ap.mac, addr3=self.ap.mac) \
                     / Dot11Beacon(cap=0x3101)                                                           \
                     / Dot11Elt(ID='SSID', info=ssid)                                                    \
                     / Dot11Elt(ID='Rates', info=AP_RATES)                                               \
                     / Dot11Elt(ID='DSset', info=chr(self.ap.channel))

        beacon_packet = beacon_packet / RSN

        # Update sequence number
        beacon_packet.SC = self.ap.next_sc()

        # Update timestamp
        beacon_packet[Dot11Beacon].timestamp = self.ap.current_timestamp()

        # Send
        sendp(beacon_packet, iface=self.ap.interface, verbose=False)

    def dot11_auth(self, receiver):
        auth_packet = self.ap.get_radiotap_header() \
                      / Dot11(subtype=0x0B, addr1=receiver, addr2=self.ap.mac, addr3=self.ap.mac, SC=self.ap.next_sc()) \
                      / Dot11Auth(seqnum=0x02)

        printd("Sending Authentication (0x0B)...", Level.DEBUG)
        sendp(auth_packet, iface=self.ap.interface, verbose=False)

    def dot11_ack(self, receiver):
        ack_packet = self.ap.get_radiotap_header() \
                     / Dot11(type='Control', subtype=0x1D, addr1=receiver)

        print("Sending ACK (0x1D) to %s ..." % receiver)
        sendp(ack_packet, iface=self.ap.interface, verbose=False)

    def dot11_assoc_resp(self, receiver, reassoc):
        response_subtype = 0x01
        if reassoc == 0x02:
            response_subtype = 0x03
        assoc_packet = self.ap.get_radiotap_header() \
                       / Dot11(subtype=response_subtype, addr1=receiver, addr2=self.ap.mac, addr3=self.ap.mac, SC=self.ap.next_sc()) \
                       / Dot11AssoResp(cap=0x3101, status=0, AID=self.ap.next_aid()) \
                       / Dot11Elt(ID='Rates', info=AP_RATES)

        printd("Sending Association Response (0x01)...", Level.DEBUG)
        sendp(assoc_packet, iface=self.ap.interface, verbose=False)

    def unspecified_raw(self, raw_data):
        raw_packet = str(raw_data)

        printd("Sending RAW packet...", Level.DEBUG)
        sendp(raw_packet, iface=self.ap.interface, verbose=False)

