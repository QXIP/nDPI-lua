Introduction
------------

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

Run
---

* Type `run`

```bash
run
```
