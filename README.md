# USB Keystroke Injection Protection
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## Overview
This tool is a daemon for blocking USB keystroke injection devices on Linux systems.

It supports two different modes of operation: **monitoring** and **hardening**. In
monitor mode, information about a potentially attacking USB device is collected
and logged to syslog. In hardening mode, the attacking USB device is ejected
from the operating system by unbinding the driver.

### Installation Prerequisites
The installation is mainly handled by `setup.sh`, however, there are some prerequisites 
that need to be adjusted before running the script:

1) Install Python3.7 or later, python dev package, virtualenv (`python3-venv`) and PIP3 (`python3-pip`) if not already 
available on the system.

1) Adjust the `KEYSTROKE_WINDOW` variable on top of the `setup.sh` file. This is the 
number of keystrokes the daemon looks at to determine whether its dealing with an attack or not. 
The lower the number, the higher the false positives will be (e.g., if the number is 2, the tool 
looks at only 1 interarrival time between those two keystrokes to determine whether it's an 
attack or not. Obviously, users sometimes hit two keys almost at the same time, which leads 
to the aforementioned false positive). Based on our internal observations, 5 is a value that 
is effective. However, it should be adjusted based on specific users' experiences and typing 
behaviour.

1) Adjust the `ABNORMAL_TYPING` variable on top of the `setup.sh` file. This variable 
specifies what interarrival time (between two keystrokes) should be classified as malicious. 
The higher the number, the more false-positives will arise (normal typing speed will be 
classified as malicious), where more false-negatives will arise with a lower number (even very 
fast typing attacks will be classified as benign). That said, the preset `50000` after initial 
installation is a safe default but should be changed to a number reflecting the typing speed of 
the user using the tool.

1) Set the mode the daemon should run in by adjusting the `RUN_MODE` variable on top of the 
`setup.sh` file. Setting it to `MONITOR` will send information about the USB device to a logging 
instance without blocking the device. Setting the variable to `HARDENING` will remove an 
attacking device from the system by unbinding the driver.

1) Adjust the `DEBIAN` variable on top of the `setup.sh` file. This variable indicates 
whether the system the tool is installed on is a Debian derivate or something else. This determination 
is important for the installation of the systemd service later on (the path, the service will be 
copied to).

1) Adjust the allowlist file in `data/allowlist`. This file will be installed to `/etc/ukip/` 
on your system and taken as source of truth for allowed devices, in case a device is 
exceeding the preset `ABNORMAL_TYPING` speed. As described in the file, the allowed device 
can be narrowed down with a specific set of characters to allow to even more minimize the attack 
surface. For example, if your keyboard uses a macro that sends `rm -rf /` allow those characters, 
and even an attacking device spoofing your keyboards product ID and vendor ID couldn't inject an 
attack (except an attack using those specific characters obviously :D ). For other cases, the 
`any` keyword allows all possible characters for a specified device and `none` disallows 
all characters. Please keep in mind that this allowlist will only be taken into consideration, if
a device is exceeding the set threshold.  

1) Adjust the keycodes file in `data/keycodes`. This file stores the relation between scancodes 
sent by the keyboard and keycodes you see on the keyboard. The default keycodes file as it is now 
has the scancode<->keycode layout for the US keyboard layout. If you are using a different layout, 
please adjust the file to fit your needs.

### Installation
Once all of the above prerequisites are fulfilled, `setup.sh` should do the rest. It will install 
depending libraries into your users home directory (`$HOME/.ukip/`) so you don't have to install 
them system wide:
```
chmod +x setup.sh
./setup.sh
```
That's it: The daemon will be automatically started at boot time.  

For interaction with the service, the systemd interface is probably the most convenient one.
To check the status:
```
systemctl status ukip.service
```

To stop the service:
```
sudo systemctl stop ukip.service
```

Alternatively, to disable the service and prevent it from being started at boot time:
```
sudo systemctl disable ukip.service
```

## Terms of use

### USB Keystroke Injection Protection
This project provides code that can be run on Linux systems to harden those systems against keystroke injection attacks, delivered via USB.
The terms of use apply to data provided by Google or implicitly through code in this repository.

```
This tool hereby grants you a perpetual, worldwide, non-exclusive,
no-charge, royalty-free, irrevocable copyright license to reproduce, prepare
derivative works of, publicly display, publicly perform, sublicense, and
distribute code in this repository related to this tool. Any copy you make for
such purposes is authorized provided that you reproduce this tool's copyright
designation and this license in any such copy.
```

### Third-party Libraries
This project builds upon several open source libraries.  
Please see each projects' Terms of use when using the provided code in this repository.

## Disclaimer
**This is not an officially supported Google product.**
