<p align="center">
<img src="http://www.ntop.org/wp-content/uploads/2015/05/ntop.png" alt="NTOP">
</p>

# nDPI-lua

Proof-of-Concept lua binding based on ndpireader and nDPI from [NTOP](http://ntop.org)

This library is aimed to be used from a Lua program.

The ```main.lua``` file reads a pcap file and inspects each packet. For each successfully associated packet and action is triggered. The actions are defined as Lua functions and follows this template:

```lua
function f(id, packet)

end
```

Where:

   * *id*, is the protocol ID.
   * *packet*, is a pcap packet (```const uint8_t *packet```).

Dependencies
------------

This program depends on libndpi 1.x. nDPI is a Deep Packet Inspection library, programmed in C.

Headers of nDPI are at ```include/```, and an already build library is at ```lib/```.

Compile
-------

* Make libndpilua.so

```bash
$ make
```

Builds libndpilua.so and places it at src/

Usage
---


```bash
luajit main.lua /path/to/file.pcap
```



Run Test
---

* Type `run`

```bash
run
```


Test Output
---
```
nDPI Memory statistics:
	nDPI Memory (once):      91.02 KB     
	Flow Memory (per flow):  1.92 KB      
	Actual Memory:           1.75 MB      
	Peak Memory:             1.75 MB      

Traffic statistics:
	Ethernet bytes:        210941        (includes ethernet CRC/IFC/trailer)
	Discarded bytes:       22728        
	IP packets:            465           of 871 packets total
	IP bytes:              199781        (avg pkt size 229 bytes)
	Unique flows:          86           
	TCP Packets:           406          
	UDP Packets:           58           
	VLAN Packets:          0            
	MPLS Packets:          0            
	PPPoE Packets:         0            
	Fragmented Packets:    0            
	Max Packet size:       1480         
	Packet Len < 64:       259          
	Packet Len 64-128:     34           
	Packet Len 128-256:    22           
	Packet Len 256-1024:   55           
	Packet Len 1024-1500:  95           
	Packet Len > 1500:     0            
	nDPI throughput:       68.68 K pps / 237.68 Mb/sec
	Traffic throughput:    8.67 pps / 30.71 Kb/sec
	Traffic duration:      53.663 sec
	Guessed flow protos:   22           


Detected protocols:
	Unknown              packets: 39            bytes: 2578          flows: 25           
	DNS                  packets: 17            bytes: 2365          flows: 10           
	HTTP                 packets: 138           bytes: 51961         flows: 12           
	NTP                  packets: 10            bytes: 900           flows: 5            
	DHCP                 packets: 3             bytes: 1038          flows: 3            
	IMAPS                packets: 33            bytes: 10093         flows: 2            
	ICMP                 packets: 1             bytes: 300           flows: 1            
	SSL                  packets: 132           bytes: 51325         flows: 14           
	Twitter              packets: 2             bytes: 324           flows: 1            
	DropBox              packets: 10            bytes: 5103          flows: 3            
	YouTube              packets: 2             bytes: 984           flows: 2            
	Google               packets: 74            bytes: 72304         flows: 7            
	Spotify              packets: 4             bytes: 506           flows: 1            


Protocol statistics:
	Safe                         61418 bytes
	Acceptable                  134295 bytes
	Fun                           1490 bytes
	Unrated                       2578 bytes
Total packets: 871

```


