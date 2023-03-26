import platform
from scapy.layers.dot11 import *

RUNNING_ON_PI = platform.machine() == 'armv6l'
DEFAULT_DNS_SERVER = "8.8.8.8"

# CCMP, PSK=WPA2
eRSN = Dot11EltRSN(
        ID=48,
        len=20,
        version=1,
        mfp_required=0,
        mfp_capable=0,
        group_cipher_suite=RSNCipherSuite(cipher='CCMP-128'),
        nb_pairwise_cipher_suites=1,
        pairwise_cipher_suites=RSNCipherSuite(cipher='CCMP-128'),
                nb_akm_suites=1,
        akm_suites=AKMSuite(suite='PSK')
    )
RSN = eRSN.build()

AP_WLAN_TYPE_OPEN = 0
AP_WLAN_TYPE_WPA = 1
AP_WLAN_TYPE_WPA2 = 2
AP_WLAN_TYPE_WPA_WPA2 = 3
AP_AUTH_TYPE_OPEN = 0
AP_AUTH_TYPE_SHARED = 1
AP_RATES = b"\x0c\x12\x18\x24\x30\x48\x60\x6c"

DOT11_MTU = 4096

DOT11_TYPE_MANAGEMENT = 0
DOT11_TYPE_CONTROL = 1
DOT11_TYPE_DATA = 2

DOT11_SUBTYPE_DATA = 0x00
DOT11_SUBTYPE_PROBE_REQ = 0x04
DOT11_SUBTYPE_AUTH_REQ = 0x0B
DOT11_SUBTYPE_ASSOC_REQ = 0x00
DOT11_SUBTYPE_REASSOC_REQ = 0x02
DOT11_SUBTYPE_QOS_DATA = 0x28


IFNAMSIZ = 16
IFF_TUN = 0x0001
IFF_TAP = 0x0002  # Should we want to tunnel layer 2...
IFF_NO_PI = 0x1000
TUNSETIFF = 0x400454ca
