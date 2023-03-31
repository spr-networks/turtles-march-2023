🐢 ~ Welcome to Turtles WiFi Challenges - march 2023 ~ 🐢

## Notes

click "browse files" button, select p.pcap to inspect packets.


# Part 0 Challenges (warmup):

For each challenge your goal is to uncover a password, or flag, of the form turtles{...}

To start off with, we are going to look at some pcaps.

### turtle0.pcap

We've captured a 4-way handshake. What is the key?

HINT: all PSKs are of the form turtle{???} where ??? is a password. 

### turtle0.5.pcap

HINT: there's some data to decode


# Part 1 

fakeap/go.py is a python AP written in scapy.

It implements WPA2 using AES CCMP. 

See if you can crack the PSK in turtle1-handshake.pcap
The format of the PSK is turtle{???} where ??? is a password.

# Part 2

turtleap is running on the system. Can you break into the network and hack the AP?

