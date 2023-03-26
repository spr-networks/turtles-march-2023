# turtles-march

## Play Online

You can play online here [https://turtles.supernetworks.org/march](https://turtles.supernetworks.org/march)
<img width="1328" alt="Screen Shot 2023-03-25 at 10 03 57 PM" src="https://user-images.githubusercontent.com/37549748/227756388-3d733639-b17f-4392-9e59-c177940d9b27.png">


<img width="1323" alt="Screen Shot 2023-03-25 at 10 03 42 PM" src="https://user-images.githubusercontent.com/37549748/227756372-9c8172f4-6db9-477c-a3ac-2177514e66ef.png">

## Self host with docker

You can use docker-compose.yml to self host your challenge

## Previous Challenges

* [January](https://github.com/spr-networks/turtles-january-23/)
* [February](https://github.com/spr-networks/turtles-feb-2023/)

## Dependencies
See host-install.sh. Make sure wireless-regdb is installed on the host, along with the mac hwsim drivers. It was observed that missing the regulatory db on the host stops the challenges from running correctly.

## Running the system
```
docker-compose up -d
sudo ./setup.sh

docker exec -it t1_start bash or ssh root@localhost -p 2222 (password is march_turtle_madness)
```

## Rules

1. Submit writeups by e-mail to turtles at supernetworks.org (April 20th is the deadline)

2. The best writeup along with the first two correct submissions will be awarded pis as prizes. Writeups should include functional exploits

3. You can get the challenges here: https://github.com/spr-networks/turtles-march-2023 and a web-hosted version is available at https://turtles.supernetworks.org/march

## About
@ ChatGPT
Welcome to the electrifying WiFi Hacking Challenge, where participants test their prowess in network infiltration and compete for the grand prize: a cutting-edge Raspberry Pi! In this adrenaline-pumping competition, aspiring hackers will face a series of trials designed 
to assess their skills in various aspects of WiFi security. The first part of the challenge dives into cracking Pre-Shared Keys (PSKs) within the Extensible Authentication Protocol over LAN (EAPOL). Contestants will be tasked with exploiting vulnerabilities in wireless 
networks using an array of techniques, such as capturing handshakes, decrypting packets, and brute-forcing passwords. Armed with their trusty tools and unyielding determination, participants must showcase their exceptional abilities in this arena, striving to unravel the 
intricacies of PSKs in EAPOL. The stakes are high, and only the most skilled WiFi warriors will emerge victorious, earning the coveted Raspberry Pi and the admiration of their peers.

