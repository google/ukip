#!/usr/bin/env python3
# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import collections
import gc
import json
import logging
import logging.handlers
import sys
import threading
import attr
import enum
import evdev
import pyudev
from typing import Text
import usb


# Modes, available for UKIP to run in. Constant enum:
# 1) MONITOR: Sends information about the usb device to a logging instance.
# 2) HARDENING: The device gets removed from the system (drivers are unbound
#    from every device interface).
class UKIP_AVAILABLE_MODES(enum.Enum):
  MONITOR = 'MONITOR'
  HARDENING = 'HARDENING'


# The current mode, UKIP is running in.
_UKIP_RUN_MODE = UKIP_AVAILABLE_MODES.HARDENING

# A dict with ringbuffers as values (holding the most recent 5 keystroke times):
# keys are paths to the event devices.
_event_devices_timings = {}

# A dict with ringbuffers as values (holding the most recent 5 keystrokes):
# keys are paths to the event devices.
_event_devices_keystrokes = {}

# Window of keystrokes to look at.
KEYSTROKE_WINDOW = 5

# Abnormal typing threshold in milliseconds (Linux emits keystroke timings in
# microsecond precision).
# Lower: More True Positives.
# Higher: More False Positives.
ABNORMAL_TYPING = 50000

# 1 equals KEY_DOWN in evdev.
KEY_DOWN = evdev.KeyEvent.key_down

# Shifts as constants for better readability.
LSHIFT = 42
RSHIFT = 54

# Turn off duplicate logging to syslog, that would happen with the root logger.
logging.basicConfig(filename='/dev/null', level=logging.DEBUG)
# Now, turn on logging to syslog.
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
handler = logging.handlers.SysLogHandler(address='/dev/log')
log.addHandler(handler)

# Global lock for _event_devices_timings and _event_devices_keystrokes dicts.
_event_devices_lock = threading.Lock()


@attr.s
class AllowlistConfigReturn(object):
  """Class to represent the return value of the allowlist Config.

  The following return combinations are valid:
  1) allowlist is a list with characters, device_present is true: the returned
  characters are not blocked by UKIP for the given device.
  2) allowlist is an empty list, device_present is true: for the given device,
  any character is allowed by UKIP.
  3) allowlist is an empty list, device_present is false: for the given device,
  no character is allowed by UKIP (either the device is not in the config
  file, or a user specifically marked that device with 'none' for the allowed
  characters).

  Attributes:
   allowlist: The returned allowlist, or empty if all characters are allowed.
   device_present: A boolean, whether the device was found in the config file.
  """
  allowlist = attr.ib()  # type: list
  device_present = attr.ib()  # type: boolean


@attr.s
class KeycodesReturn(object):
  """Class to represent the return value of the keycode file read.

  The keycode file in /etc/ukip/keycodes contains the scancodes and ASCII
  codes for the selected keyboard layout. It is parsed once and read into two
  dicts for further processing: lower_codes and capped_codes.
  """
  lower_codes = attr.ib()  # type: dict
  capped_codes = attr.ib()  # type: dict


class DeviceError(Exception):
  """Generic error class for device processing."""


class AllowlistFileError(Exception):
  """Generic error class for allowlist processing."""


class KeycodesFileError(Exception):
  """Generic error class for keycode file processing."""


def add_to_ring_buffer(event_device_path: Text, key_down_time: int,
                       keystroke: Text, device: usb.core.Device):
  """Add time in milliseconds to global ringbuffer.

  Locates the event device (/dev/input/*) in the dict of ringbuffers and adds
  the KEY_DOWN time in milliseconds to it. Then calls the check_for_attack
  function on the event device and the usb core device.

  Args:
    event_device_path: The path to the event device (/dev/input/*).
    key_down_time: The KEY_DOWN time in milliseconds.
    keystroke: The actual key typed.
    device: A USB device (usb.core.Device).
  """
  with _event_devices_lock:
    if event_device_path not in _event_devices_timings:
      _event_devices_timings[event_device_path] = collections.deque(
          maxlen=KEYSTROKE_WINDOW)
      _event_devices_keystrokes[event_device_path] = collections.deque(
          maxlen=KEYSTROKE_WINDOW)

    _event_devices_timings[event_device_path].append(key_down_time)
    _event_devices_keystrokes[event_device_path].append(keystroke)

  check_for_attack(event_device_path, device)


def check_local_allowlist(product_id: Text,
                          vendor_id: Text) -> AllowlistConfigReturn:
  """Check local (user-based) allowlist for specifically allowed devices.

  UKIP users are able to specify USB devices they want to allow in a local
  file. This allowlist is checked, when a device is found attacking (timing
  threshold is exceeded) and whether that device is listed in here. If so, only
  the characters listed in the corresponding allowlist are allowed, the others
  are denied (in case of 'any' and 'none' all or no characters are allowed
  respectively). If the device is not listed in the allowlist, it is denied per
  default.

  Args:
    product_id: The required product ID to look up in the local allowlist.
    vendor_id: The required vendor ID to look up in the local allowlist.

  Raises:
    AllowlistFileError: When there were errors with the allowlist config file.

  Returns:
    A AllowlistConfigReturn object, with the following variations:
    1) allowlist is a list with characters, device_present is true: the returned
    characters are not blocked by UKIP for the given device.
    2) allowlist is an empty list, device_present is true: for the given device
    any character is allowed by UKIP.
    3) allowlist is an empty list, device_present is false: for the given device
    no character is allowed by UKIP (either the device is not in the config
    file, or a user specifically marked that device with 'none' for the allowed
    characters).
  """
  device = '%s:%s' % (product_id, vendor_id)

  try:
    with open('/etc/ukip/allowlist', 'r') as f:
      for line in f:
        # Comments start with '#'.
        if line[0] == '#':
          continue
        # Ignore empty lines.
        if not line.strip():
          continue

        try:
          (key, val) = line.split()
          int(key.split(':')[0], 16)
          int(key.split(':')[1], 16)

          allowlist = val.split(',')

          if key != device:
            continue
          if allowlist[0] == 'any':
            return AllowlistConfigReturn(allowlist=[], device_present=True)
          if allowlist[0] == 'none':
            return AllowlistConfigReturn(allowlist=[], device_present=False)

          # If all of the checks succeed, return the allowlist (but only if it
          # is an allowlist, and not a word).
          if len(allowlist[0]) == 1:
            return AllowlistConfigReturn(
                allowlist=val.split(','), device_present=True)
        except (ValueError, IndexError) as vi:
          raise AllowlistFileError(
              'The format of the config file /etc/ukip/allowlist seems to be'
              ' incorrect: %s' % vi)

      # If the device wasn't found in the file, return False.
      return AllowlistConfigReturn(allowlist=[], device_present=False)
  except FileNotFoundError as fnfe:
    raise AllowlistFileError(
        'The config file /etc/ukip/allowlist could not be found: %s' % fnfe)


def check_for_attack(event_device_path: Text, device: usb.core.Device) -> bool:
  """Check a ringbuffer of KEY_DOWN timings for attacks.

  Locates the event device (/dev/input/*) in the dict of ringbuffers and checks
  the correct ringbuffer for attacks (keystroke injection attack). In case of
  an attack, two actions can be taken, depending on the mode UKIP is running in.
  Those modes are specified in the UKIP_AVAILABLE_MODES enum.

  Args:
    event_device_path: The path to the event device (/dev/input/*).
    device: A USB device (usb.core.Device).

  Returns:
    False: If the check failed (not enough times, mode not set). None otherwise.
  """
  with _event_devices_lock:
    if len(_event_devices_timings[event_device_path]) < KEYSTROKE_WINDOW:
      return False

    attack_counter = 0

    # Count the number of adjacent keystrokes below (or equal) the
    # ABNORMAL_TYPING.
    reversed_buffer = reversed(_event_devices_timings[event_device_path])
    for value in reversed_buffer:
      for prev in reversed_buffer:
        if value - prev <= ABNORMAL_TYPING:
          attack_counter += 1
        value = prev
      break  # Exit after the first backward iteratation.

  # If all the timings in the ringbuffer are within the ABNORMAL_TYPING timing.
  if attack_counter == KEYSTROKE_WINDOW - 1:
    if _UKIP_RUN_MODE == UKIP_AVAILABLE_MODES.MONITOR:
      enforce_monitor_mode(device, event_device_path)
    elif _UKIP_RUN_MODE == UKIP_AVAILABLE_MODES.HARDENING:
      enforce_hardening_mode(device, event_device_path)
    else:
      log.error('No run mode was specified for UKIP. Exiting...')
      return False


def enforce_monitor_mode(device: usb.core.Device, event_device_path: Text):
  """Enforce the MONITOR mode on a given device.

  Information about devices, that would have been blocked in HARDENING mode
  is logged to /dev/log.

  Args:
    device: A USB device (usb.core.Device).
    event_device_path: The path to the event device (/dev/input/*).
  """
  log.warning(
      '[UKIP] The device %s with the vendor id %s and the product id'
      ' %s would have been blocked. The causing timings are: %s.',
      device.product if device.product else 'UNKNOWN', hex(device.idVendor),
      hex(device.idProduct), _event_devices_timings[event_device_path])


def enforce_hardening_mode(device: usb.core.Device, event_device_path: Text):
  """Enforce the HARDENING mode on a given device.

  When enforcing the HARDENING mode, a device gets removed from the operating
  system when the keystrokes exceed the typing speed threshold
  (ABNORMAL_TYPING). This is done by unbinding the drivers from every device
  interface. Before the device is removed, the allowlist is checked. If the
  product and vendor ids are in there, the function will return and the device
  will continue working (possibly with a reduced allowed character set, as
  described in the function check_local_allowlist).

  Args:
    device: A USB device (usb.core.Device).
    event_device_path: The path to the event device (/dev/input/*).
  """

  product_id = hex(device.idProduct)
  vendor_id = hex(device.idVendor)

  local_allowlist = check_local_allowlist(
      hex(device.idProduct), hex(device.idVendor))

  # Device is present in the allowlist and all characters are allowed.
  if local_allowlist.device_present and not local_allowlist.allowlist:
    return
  # Device is present and an allowlist is specified.
  elif local_allowlist.device_present and local_allowlist.allowlist:
    allowlist = local_allowlist.allowlist
  # Device is not in the allowlist or keyword is 'none'.
  # i.e.: not local_allowlist.device_present and not local_allowlist.allowlist
  else:
    allowlist = []

  # If all typed characters are in the allowlist, return. Otherwise run through
  # the rest of the function.
  if not set(_event_devices_keystrokes[event_device_path]).difference(
      set(allowlist)):
    return

  pid_and_vid = '%s:%s' % (product_id, vendor_id)

  for config in device:
    for interface in range(config.bNumInterfaces):
      if device.is_kernel_driver_active(interface):
        try:
          device.detach_kernel_driver(interface)

          if device.product:
            log.warning(
                '[UKIP] The device %s with the vendor id %s and the '
                'product id %s was blocked. The causing timings were: '
                '%s.', device.product, vendor_id, product_id,
                _event_devices_timings[event_device_path])
          else:
            log.warning(
                '[UKIP] The device with the vendor id %s and the '
                'product id %s was blocked. The causing timings were: '
                '%s.', vendor_id, product_id,
                _event_devices_timings[event_device_path])

        except (IOError, OSError, ValueError, usb.core.USBError) as e:
          log.warning(
              'There was an error in unbinding the interface for the USB device'
              ' %s: %s', pid_and_vid, e)
          # In case of an error we still need to continue to the next interface.
          continue

  # The device was removed, so clear the dicts. Most importantly, clear the
  # keystroke dict.
  del _event_devices_timings[event_device_path]
  del _event_devices_keystrokes[event_device_path]
  gc.collect()


def load_keycodes_from_file() -> KeycodesReturn:
  """Helper function to load the keycodes file into memory.

  Returns:
    The lowcodes and capscodes as dicts in a KeycodesReturn attribute.
  Raises:
    KeycodesFileError: If there is a problem with the keycodes file.
  """
  lowcodes = {}
  capscodes = {}

  try:
    with open('/etc/ukip/keycodes', 'r') as keycode_file:
      try:
        keycodes = json.load(keycode_file)
      except (OverflowError, ValueError, TypeError) as je:
        raise KeycodesFileError('The keycodes file could not be read: %s' % je)
  except FileNotFoundError as fnfe:
    raise KeycodesFileError(
        'The keycode file /etc/ukip/keycodes could not be found: %s' % fnfe)

  if not keycodes.get('lowcodes') or not keycodes.get('capscodes'):
    log.error(
        'The keycodes file is missing either the lowcodes or capscodes keyword.'
    )
    return KeycodesReturn(lower_codes=lowcodes, capped_codes=capscodes)

  for keycode in keycodes['lowcodes']:
    for scancode, lowcode in keycode.items():
      lowcodes[int(scancode)] = lowcode

  for keycode in keycodes['capscodes']:
    for scancode, capcode in keycode.items():
      capscodes[int(scancode)] = capcode

  return KeycodesReturn(lower_codes=lowcodes, capped_codes=capscodes)


def monitor_device_thread(device: pyudev.Device, vendor_id: int,
                          product_id: int) -> None:
  """Monitor a given USB device for occurring KEY_DOWN events.

  Creates a passive reading loop over a given event device and waits for
  KEY_DOWN events to occour. Then extracts the time in milliseconds of the event
  and adds it to the ringbuffer.

  Args:
    device: The event device in (/dev/input/*).
    vendor_id: The vendor ID of the device.
    product_id: The product ID of the device.

  Raises:
    OSError: If the given USB device cannot be found or if the OS receives
             keyboard events, after the device was unbound. Both originate from
             the evdev lib.
    StopIteration: If the iteration of the usb device tree breaks.
  """
  keycodes = load_keycodes_from_file()
  lowcodes = keycodes.lower_codes
  capscodes = keycodes.capped_codes

  try:
    try:
      inputdevice = evdev.InputDevice(device.device_node)
      dev = usb.core.find(idVendor=vendor_id, idProduct=product_id)
    except (OSError, StopIteration) as mex:
      log.warning(
          'There was an error while starting the thread for device monitoring:'
          ' %s', mex)

      # Bail the function and with that, end the thread.
      return

    log.info(
        f'Start monitoring {device.device_node} with the VID {hex(vendor_id)} and the PID {hex(product_id)}'
    )

    try:
      # The default behaviour of evdev.InputDevice is a non-exclusive access,
      # so each reader gets a copy of each event.
      for event in inputdevice.read_loop():
        caps = False

        for led in inputdevice.leds(verbose=True):
          # Check if CapsLock is turned on.
          if 'LED_CAPSL' in led:
            caps = True

        # LShift or RShift is either pressed or held.
        if LSHIFT in inputdevice.active_keys(
        ) or RSHIFT in inputdevice.active_keys():
          caps = True

        if event.value == KEY_DOWN and event.type == evdev.ecodes.EV_KEY:
          keystroke_in_ms = (event.sec * 1000000) + event.usec

          if caps:
            keystroke = capscodes.get(evdev.categorize(event).scancode)
          else:
            keystroke = lowcodes.get(evdev.categorize(event).scancode)

          add_to_ring_buffer(device.device_node, keystroke_in_ms, keystroke,
                             dev)

    except OSError as ose:
      log.warning('Events found for unbound device: %s', ose)
  except:
    log.exception('Error monitoring device.')


def init_device_list() -> int:
  """Adds all current event devices to the global dict of event devices.

  Returns:
    The number of event devices connected, at the time UKIP was started.
  Raises:
    TypeError: If there is an error in converting the PID/VID of a USB device.
    ValueError: If there is an error in converting the PID/VID of a USB device.
    RuntimeError: If there is an error in launching the thread.
    DeviceError: If there is an error in creating the device list.
  """

  device_count = 0

  try:
    local_device_context = pyudev.Context()
    local_device_monitor = pyudev.Monitor.from_netlink(local_device_context)
    local_device_monitor.filter_by(subsystem='input')
  except (ValueError, EnvironmentError, DeviceError) as mex:
    log.warning(
        'There was an error creating the initial list of USB devices: %s', mex)
    raise DeviceError('The device context and monitor could not be created.')

  for device in local_device_context.list_devices():
    if device.device_node and device.device_node.startswith(
        '/dev/input/event') and (device.get('ID_VENDOR_ID') and
                                 device.get('ID_MODEL_ID')):

      try:
        vendor_id = int(device.get('ID_VENDOR_ID'), 16)
        product_id = int(device.get('ID_MODEL_ID'), 16)
      except (TypeError, ValueError) as mex:
        log.error(
            'There was an error in converting the PID and VID of a USB device: '
            '%s', mex)
        continue

      try:
        threading.Thread(
            target=monitor_device_thread,
            args=(device, vendor_id, product_id)).start()
        device_count += 1
      except RuntimeError as e:
        log.error(
            'There was an runtime error in starting the monitoring thread %s',
            e)

  return device_count


def main(argv):
  if len(argv) > 1:
    sys.exit('Too many command-line arguments.')

  device_count = init_device_list()

  if not device_count:
    log.warning('No HID devices connected to this machine yet')

  #####################
  # Hotplug detection #
  #####################
  context = pyudev.Context()
  monitor = pyudev.Monitor.from_netlink(context)
  monitor.filter_by(subsystem='input')

  for device in iter(monitor.poll, None):
    try:
      if device.action == 'add':
        if device.device_node and '/dev/input/event' in device.device_node and (
            device.get('ID_VENDOR_ID') and device.get('ID_MODEL_ID')):

          try:
            vendor_id = int(device.get('ID_VENDOR_ID'), 16)
            product_id = int(device.get('ID_MODEL_ID'), 16)
          except (TypeError, ValueError) as mex:
            log.error(
                'There was an error in converting the PID and VID of a USB'
                ' device: %s', mex)
            continue

          threading.Thread(
              target=monitor_device_thread,
              args=(device, vendor_id, product_id)).start()
    except:
      log.exception('Error adding new device to monitoring.')


if __name__ == '__main__':
  sys.exit(main(sys.argv))
