# pppoe-atm-relay - relay between PPPoA and PPPoE protocols

pppoe-atm-relay is a PPP packet relay between Ethernet and ATM interfaces. It enables a completely transparent connection of PPPoE clients (e.g. routers, servers, computers) with ATM interfaces (ADSL, VDSL, DOCSIS technologies, as well as pure ATM network cards). This is not Ethernet over ATM - PPPoE frames are decapsulated into individual PPP packets and transmitted via the ATM interface and vice versa.

# Installation

Build the pppoe-atm-relay using `cmake` and create a service using the solution used on your machine (e.g. systemd, init.d).
pppoe-atm-relay requires a kernel with PPPoA and PPPoE support (`CONFIG_PPPOE`, `CONFIG_PPPOATM`).

By setting the `AC_NAME` parameter in cmake or compiling directly with the compiler, you can change the AC Name that pppoe-atm-relay presents to clients from the default `pppoe-atm-relay`.

**pppoe-atm-relay requires at least kernel version 5.11**, as it uses the PPPIOCBRIDGECHAN functionality. However, when building your own embedded system, you are probably able to backport the relevant [commit](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=4cf476ced45d7f12df30a68e833b263e7a2202d1) (SHA: 4cf476ced45d7f12df30a68e833b263e7a2202d1) and all patches released after it (of course).
Alternatively, you could modify pppoe-atm-relay to manually transfer data between PPP channels, but this would slow down the relay's performance.

`However, I encourage you to build your embedded systems with the latest kernel versions possible.`

# Usage
```
pppoe-atm-relay [options]
Options:
    -h: Show help
    -v: Show version
    -i: Ethernet device to listen on (default: eth0)
    -f: Run in foreground
```

Both in the foreground and in the background, pppoe-atm-relay writes logs to syslog, except for critical messages at startup (hence so quiet in the foreground).

# Connecting with a client

PPPoE clients usually do not have the option to set ATM interface parameters, which is why pppoe-atm-relay uses the Service-Name tag to specify which path, channel and encapsulation to use.

The Service-Name tag must have the following structure:

`<ATM interface>.<VPI>.<VCI>,<Encapsulation>`

where `<Encapsulation>`: 0 - auto-detection, 1 - VC-MUX, 2 - LLC

For example, ‘0.0.35,2’ means ATM interface no. 0, VPI=0, VCI=35 and LLC encapsulation. **Please note that there is a comma between VCI and encapsulation instead of a dot.**

pppoe-atm-relay also supports RFC 4638, so you can set a larger MRU than 1492, but the Ethernet interface on which the relay listens must have an increased MTU, otherwise the relay will enforce an MTU of 1492.

All other parameters of the PPP protocol itself (such as login and password) are irrelevant for pppoe-atm-relay, as PPP packets are transparently forwarded between interfaces.