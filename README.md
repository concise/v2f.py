**WARNING:**  This project is still in its pre-alpha stage.  Serious refactoring
and documentations are needed.


# v2f.py is a virtual U2F device

Currently v2f.py only supports Linux, because UHID ABI is pretty handy.  I only
tested the code in a 64-bit Ubuntu 16.04 desktop environment with Google Chrome.

To clone this source code repository

```bash
git clone https://github.com/concise/v2f.py
cd v2f.py
```


To run v2f (default: store everything under ~/.v2f directory)

```bash
python3 v2f.py
```


To run v2f with a specified device information directory

```bash
python3 v2f.py ~/.my-v2f-info-dir
```



### You may need to tweak permissions of some files before running v2f.py

To make `/dev/uhid` universally read-writable, chmod it after opening it at
least once

```bash
sudo dd if=/dev/uhid count=0
sudo chmod 0666 /dev/uhid
```


To make `/dev/uhid` universally read-writable across rebooting

```bash
sudo tee <<< $'#!/bin/sh -e\n> /dev/uhid\n/bin/chmod 0666 /dev/uhid\nexit 0' /etc/rc.local
```


To make `/dev/hidraw*` devices universally read-writable

```bash
sudo tee <<< 'KERNEL=="hidraw*", SUBSYSTEM=="hidraw", MODE="0666"' /etc/udev/rules.d/99-hack-hidraw.rules
```
