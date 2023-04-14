Here are some useful notes on how to set up addr1/addr2/addr3 in your scapy packets. If addr1 is wrong, the underlying mac80211-hwsim system may not see them via the linux ieee80211 stack and if the FromDS/ToDS are wrong in relation tothe addr combos the receiver may parse incorrectly.


https://www.oreilly.com/library/view/80211-wireless-networks/0596100523/ch04.html
```
Function   ToDS   FromDS   ADDR1 (receiver)   ADDR2 (transmitter)  ADDR3 ADDR4

IBSS-adh    0      0        DA                SA                   BSSID   n/a

TO-AP       1      0        BSSID             SA                   DA      n/a

FROM-AP     0      1        DA                BSSID                SA      n/a

WDS (br)    1      1        RA                TA                   DA      SA

```

#### Transmitter 
= who put the frame onto the radio link

#### Receiver 
= who received the frame from the radio link

### SA 
= sender address. can differ from transmitter
### DA 
= destination address. who should get it, differs from receiver
