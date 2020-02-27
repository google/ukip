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

import builtins
import collections
import gc
import json
import unittest.mock as mock
import sys
import threading
import unittest
import ukip
import evdev
import pyudev
import usb


sys.modules['evdev'] = mock.MagicMock()
sys.modules['pyudev'] = mock.MagicMock()
sys.modules['usb'] = mock.MagicMock()


# This is needed, because the whole library is (Magic)mocked.
# Therefore, without this an error is thrown, that usb.core.USBError is not
# inheriting from BaseException.
class USBError(IOError):
  pass


class UkipTest(unittest.TestCase):

  def setUp(self):
    super(UkipTest, self).setUp()

    usb.core.USBError = USBError

    ukip._event_devices_timings = {}
    ukip._event_devices_keystrokes = {}

    class FakePyudevDevice(object):
      product = None
      device_node = None
      action = None
      ID_VENDOR_ID = None
      ID_MODEL_ID = None

      def get(self, attribute):
        return getattr(self, attribute)

    class FakeEvent(object):
      value = None
      type = None
      sec = None
      usec = None
      scancode = None

    self.pyudev_device = FakePyudevDevice()
    self.pyudev_device.product = 'FakeProduct'
    self.pyudev_device.device_node = '/dev/input/event1337'
    self.pyudev_device.action = 'add'
    # Pyudev devices emit the PID and VID as strings (hex values, but str).
    # Also, the PID (product ID) is called model ID (ID_MODEL_ID).
    self.pyudev_device.ID_VENDOR_ID = '123'
    self.pyudev_device.ID_MODEL_ID = '456'

    self.fake_event = FakeEvent()
    self.fake_event.value = evdev.KeyEvent.key_down
    self.fake_event.type = evdev.ecodes.EV_KEY
    self.fake_event.sec = 13
    self.fake_event.usec = 477827
    self.fake_event.scancode = 45

    self.mock_inputdevice = mock.create_autospec(evdev.InputDevice)

    self.mock_pyusb_device = mock.MagicMock()
    self.mock_pyusb_device.product = 'SomeVendor Keyboard'
    # PyUSB devices emit the PID and VID as integers.
    self.mock_pyusb_device.idVendor = 123
    self.mock_pyusb_device.idProduct = 456
    self.mock_pyusb_device.is_kernel_driver_active.return_value = True

    self.mock_usb_config = mock.create_autospec(usb.core.Configuration)
    self.mock_usb_config.bNumInterfaces = 1

    self.event_device_path = '/dev/input/event1337'

    evdev.InputDevice.side_effect = None

  @mock.patch.object(ukip, 'enforce_monitor_mode', autospec=True)
  def test_check_for_attack_trigger_monitor(self, monitor_mode_mock):
    """Tests if the monitor mode is triggered for attacking device times."""

    ukip._UKIP_RUN_MODE = ukip.UKIP_AVAILABLE_MODES.MONITOR

    # Need to access the global variable.
    ukip._event_devices_timings[self.event_device_path] = collections.deque(
        maxlen=ukip.KEYSTROKE_WINDOW)
    ukip._event_devices_keystrokes[self.event_device_path] = collections.deque(
        maxlen=ukip.KEYSTROKE_WINDOW)

    # Push amount of KEYSTROKE_WINDOW times into the ringbuffer, that trigger
    # the monitor mode.
    ukip._event_devices_timings[self.event_device_path].append(1555146977759524)
    ukip._event_devices_timings[self.event_device_path].append(1555146977759525)
    ukip._event_devices_timings[self.event_device_path].append(1555146977759526)
    ukip._event_devices_timings[self.event_device_path].append(1555146977759527)
    ukip._event_devices_timings[self.event_device_path].append(1555146977759528)

    ukip.check_for_attack(self.event_device_path, self.mock_pyusb_device)

    # The timings trigger, so call the monitor mode.
    monitor_mode_mock.assert_called_once_with(self.mock_pyusb_device,
                                              self.event_device_path)

  @mock.patch.object(ukip, 'enforce_monitor_mode', autospec=True)
  def test_check_for_attack_not_trigger_monitor(self, monitor_mode_mock):
    """Tests if the monitor mode is NOT triggered for benign device times."""

    ukip._UKIP_RUN_MODE = ukip.UKIP_AVAILABLE_MODES.MONITOR

    # Need to access the global variable.
    ukip._event_devices_timings[self.event_device_path] = collections.deque(
        maxlen=ukip.KEYSTROKE_WINDOW)

    # Normal typing, that doesn't trigger the monitor mode.
    ukip._event_devices_timings[self.event_device_path].append(1555146977759524)
    ukip._event_devices_timings[self.event_device_path].append(1555146980127487)
    ukip._event_devices_timings[self.event_device_path].append(1555146982271470)
    ukip._event_devices_timings[self.event_device_path].append(1555146984415453)
    ukip._event_devices_timings[self.event_device_path].append(1555146986559436)

    ukip.check_for_attack(self.event_device_path, self.mock_pyusb_device)

    # Since normal typing, the monitor mode was not called.
    self.assertFalse(monitor_mode_mock.called)

  @mock.patch.object(ukip, 'enforce_monitor_mode', autospec=True)
  def test_check_for_attack_no_times(self, monitor_mode_mock):
    """Checks if function returns early, if no times are provided."""

    ukip._UKIP_RUN_MODE = ukip.UKIP_AVAILABLE_MODES.MONITOR

    ukip._event_devices_timings[self.event_device_path] = collections.deque(
        maxlen=ukip.KEYSTROKE_WINDOW)
    not_enough_timings = ukip.check_for_attack(self.event_device_path,
                                               self.mock_pyusb_device)

    # Not enough times, so bail out of the function call early (return False).
    self.assertIs(not_enough_timings, False)

    # When not enough times, return value is None and monitor mode is not
    # called.
    self.assertFalse(monitor_mode_mock.called)

  @mock.patch.object(ukip, 'enforce_hardening_mode', autospec=True)
  @mock.patch.object(ukip, 'enforce_monitor_mode', autospec=True)
  def test_check_for_attack_proper_run_mode(self, monitor_mode_mock,
                                            hardening_mode_mock):
    """Tests if the proper mode is executed based on global selection."""

    # Need to access the global variable.
    ukip._event_devices_timings[self.event_device_path] = collections.deque(
        maxlen=ukip.KEYSTROKE_WINDOW)

    # Push amount of KEYSTROKE_WINDOW times into the ringbuffer, that triggers
    # the chosen mode.
    ukip._event_devices_timings[self.event_device_path].append(1555146977759524)
    ukip._event_devices_timings[self.event_device_path].append(1555146977759525)
    ukip._event_devices_timings[self.event_device_path].append(1555146977759526)
    ukip._event_devices_timings[self.event_device_path].append(1555146977759527)
    ukip._event_devices_timings[self.event_device_path].append(1555146977759528)

    # First test with the MONITOR mode.
    ukip._UKIP_RUN_MODE = ukip.UKIP_AVAILABLE_MODES.MONITOR
    ukip.check_for_attack(self.event_device_path, self.mock_pyusb_device)
    monitor_mode_mock.assert_called_once_with(self.mock_pyusb_device,
                                              self.event_device_path)

    # Finally, test with the HARDENING mode.
    ukip._UKIP_RUN_MODE = ukip.UKIP_AVAILABLE_MODES.HARDENING
    ukip.check_for_attack(self.event_device_path, self.mock_pyusb_device)
    hardening_mode_mock.assert_called_once_with(self.mock_pyusb_device,
                                                self.event_device_path)

  @mock.patch.object(ukip, 'log', autospec=True)
  @mock.patch.object(ukip, 'enforce_hardening_mode', autospec=True)
  @mock.patch.object(ukip, 'enforce_monitor_mode', autospec=True)
  def test_check_for_attack_no_run_mode(self, monitor_mode_mock,
                                        hardening_mode_mock, logging_mock):
    """Tests when no run mode is set."""

    # Need to access the global variable.
    ukip._event_devices_timings[self.event_device_path] = collections.deque(
        maxlen=ukip.KEYSTROKE_WINDOW)

    # Push amount of KEYSTROKE_WINDOW times into the ringbuffer, that would
    # trigger a chosen mode.
    ukip._event_devices_timings[self.event_device_path].append(1555146977759524)
    ukip._event_devices_timings[self.event_device_path].append(1555146977759525)
    ukip._event_devices_timings[self.event_device_path].append(1555146977759526)
    ukip._event_devices_timings[self.event_device_path].append(1555146977759527)
    ukip._event_devices_timings[self.event_device_path].append(1555146977759528)

    # Set the run mode to None.
    ukip._UKIP_RUN_MODE = None
    ukip.check_for_attack(self.event_device_path, self.mock_pyusb_device)

    # No mode should trigger.
    self.assertFalse(monitor_mode_mock.called)
    self.assertFalse(hardening_mode_mock.called)

    # But the error should be logged.
    logging_mock.error.assert_called_once()

  @mock.patch.object(ukip, 'check_for_attack', autospec=True)
  def test_add_to_ring_buffer_create_key_time(self, check_for_attack_mock):
    """Tests the ringbuffer key creation on adding a time for the first time."""

    # At the beginning the global dict is empty.
    self.assertFalse(ukip._event_devices_timings)

    # The event_device_path wasn't present, but should be created now.
    ukip.add_to_ring_buffer(self.event_device_path, 1555146977759524, 'x',
                            self.mock_pyusb_device)

    # Check if the key was successfully created.
    self.assertTrue(ukip._event_devices_timings.get(self.event_device_path))

    # Check if the check_for_attack function was called on the created key.
    check_for_attack_mock.assert_called_once_with(self.event_device_path,
                                                  self.mock_pyusb_device)

  @mock.patch.object(ukip, 'check_for_attack', autospec=True)
  def test_add_to_ring_buffer_create_key_keystroke(self, check_for_attack_mock):
    """Tests the ringbuffer key creation on adding an initial keystroke."""

    # At the beginning the global dict is empty.
    self.assertFalse(ukip._event_devices_keystrokes)

    # The event_device_path wasn't present, but should be created now.
    ukip.add_to_ring_buffer(self.event_device_path, 1555146977759524, 'x',
                            self.mock_pyusb_device)

    # Check if the key was successfully created.
    self.assertTrue(ukip._event_devices_keystrokes.get(self.event_device_path))

    # Check if the check_for_attack function was called on the created key.
    check_for_attack_mock.assert_called_once_with(self.event_device_path,
                                                  self.mock_pyusb_device)

  @mock.patch.object(ukip, 'check_for_attack', autospec=True)
  def test_add_to_ring_buffer_multiple_values(self, check_for_attack_mock):
    """Tests if the ringbuffer is working correctly with the set window."""

    ukip.add_to_ring_buffer(self.event_device_path, 1555146977759524, 'a',
                            self.mock_pyusb_device)

    self.assertEqual(
        len(ukip._event_devices_timings.get(self.event_device_path)), 1)

    ukip.add_to_ring_buffer(self.event_device_path, 1555146980127487, 'b',
                            self.mock_pyusb_device)

    self.assertEqual(
        len(ukip._event_devices_timings.get(self.event_device_path)), 2)

    ukip.add_to_ring_buffer(self.event_device_path, 1555146980303490, 'c',
                            self.mock_pyusb_device)

    self.assertEqual(
        len(ukip._event_devices_timings.get(self.event_device_path)), 3)

    ukip.add_to_ring_buffer(self.event_device_path, 1555146982271470, 'd',
                            self.mock_pyusb_device)

    self.assertEqual(
        len(ukip._event_devices_timings.get(self.event_device_path)), 4)

    ukip.add_to_ring_buffer(self.event_device_path, 1555146984271470, 'e',
                            self.mock_pyusb_device)

    self.assertEqual(
        len(ukip._event_devices_timings.get(self.event_device_path)), 5)

    ukip.add_to_ring_buffer(self.event_device_path, 1555147982271470, 'f',
                            self.mock_pyusb_device)

    # Since it's a ringbuffer, the length for both dicts is still
    # KEYSTROKE_WINDOW.
    self.assertEqual(
        len(ukip._event_devices_timings.get(self.event_device_path)),
        ukip.KEYSTROKE_WINDOW)
    self.assertEqual(
        len(ukip._event_devices_timings.get(self.event_device_path)),
        ukip.KEYSTROKE_WINDOW)

    # The check_for_attack function was called KEYSTROKE_WINDOW + 1 times.
    self.assertEqual(check_for_attack_mock.call_count,
                     ukip.KEYSTROKE_WINDOW + 1)

  @mock.patch.object(ukip, 'log', autospec=True)
  def test_enforce_monitor_mode_with_product(self, logging_mock):
    """Tests which logging message is emitted when device has a product set."""

    self.fill_test_ringbuffer_with_data()

    ukip.enforce_monitor_mode(self.mock_pyusb_device, self.event_device_path)

    logging_mock.warning.assert_called_with(
        '[UKIP] The device %s with the vendor id %s and the product'
        ' id %s would have been blocked. The causing timings are: %s.',
        self.mock_pyusb_device.product, hex(self.mock_pyusb_device.idVendor),
        hex(self.mock_pyusb_device.idProduct),
        ukip._event_devices_timings[self.event_device_path])

  @mock.patch.object(ukip, 'log', autospec=True)
  def test_enforce_monitor_mode_no_product(self, logging_mock):
    """Tests which logging message is emitted when device has NO product set."""

    self.fill_test_ringbuffer_with_data()
    self.mock_pyusb_device.product = None

    ukip.enforce_monitor_mode(self.mock_pyusb_device, self.event_device_path)

    logging_mock.warning.assert_called_with(
        '[UKIP] The device %s with the vendor id %s and the product'
        ' id %s would have been blocked. The causing timings are: %s.',
        'UNKNOWN', hex(self.mock_pyusb_device.idVendor),
        hex(self.mock_pyusb_device.idProduct),
        ukip._event_devices_timings[self.event_device_path])

  @mock.patch.object(ukip, 'load_keycodes_from_file', autospec=True)
  @mock.patch.object(evdev, 'InputDevice', autospec=True)
  @mock.patch.object(usb.core, 'find', autospec=True)
  def test_monitor_device_thread_library_calls(self, usb_core_find_mock,
                                               input_device_mock,
                                               load_keycodes_from_file_mock):
    """Tests if all the calls to the libraries are made."""

    vendor_id = int(self.pyudev_device.ID_VENDOR_ID, 16)
    product_id = int(self.pyudev_device.ID_MODEL_ID, 16)

    ukip.monitor_device_thread(self.pyudev_device, vendor_id, product_id)

    load_keycodes_from_file_mock.assert_called()

    input_device_mock.assert_called_once_with(self.pyudev_device.device_node)
    usb_core_find_mock.assert_called_once_with(
        idVendor=vendor_id, idProduct=product_id)

  def test_monitor_device_thread_logging(self):
    """Tests the initial logging of the thread starting function."""
    # TODO Implement this test.

  @mock.patch.object(ukip, 'load_keycodes_from_file', autospec=True)
  @mock.patch.object(ukip, 'log', autospec=True)
  def test_monitor_device_thread_exception_inputdevice(
      self, logging_mock, load_keycodes_from_file_mock):
    """Tests exception and log message for the InputDevice creation."""
    log_message = ('There was an error while starting the thread for device '
                   'monitoring: %s')
    exception_message = '[Errno 19] No such device'
    exception_object = OSError(exception_message)

    evdev.InputDevice.side_effect = exception_object

    vendor_id = int(self.pyudev_device.ID_VENDOR_ID, 16)
    product_id = int(self.pyudev_device.ID_MODEL_ID, 16)

    ukip.monitor_device_thread(self.pyudev_device, vendor_id, product_id)

    load_keycodes_from_file_mock.assert_called()

    logging_mock.warning.assert_called()

  @mock.patch.object(ukip, 'load_keycodes_from_file', autospec=True)
  @mock.patch.object(ukip, 'log', autospec=True)
  def test_monitor_device_thread_exception_read_loop(
      self, logging_mock, load_keycodes_from_file_mock):
    """Tests exception and log message in read_loop."""
    log_message = 'Events found for unbound device: %s'
    exception_message = '[Errno 19] No such device'
    exception_object = OSError(exception_message)

    local_mock_inputdevice = mock.MagicMock()
    evdev.InputDevice.return_value = local_mock_inputdevice

    local_mock_inputdevice.read_loop.side_effect = exception_object

    vendor_id = int(self.pyudev_device.ID_VENDOR_ID, 16)
    product_id = int(self.pyudev_device.ID_MODEL_ID, 16)

    ukip.monitor_device_thread(self.pyudev_device, vendor_id, product_id)

    load_keycodes_from_file_mock.assert_called()

    logging_mock.warning.assert_called()

  def test_monitor_device_thread_keystroke_in_ms(self):
    """Tests if add_to_ringbuffer was called with the keystroke time in ms."""
    # TODO Implement this test.

  def test_monitor_device_thread_keystroke_shift(self):
    """Tests if add_to_ringbuffer was called with the upper case keystroke."""
    # TODO Implement this test.

  def test_monitor_device_thread_keystroke_capslock(self):
    """Tests if add_to_ringbuffer was called with the upper case keystroke."""
    # TODO Implement this test.

  @mock.patch.object(pyudev, 'Context', autospec=True)
  @mock.patch.object(pyudev.Monitor, 'from_netlink', autospec=True)
  def test_init_device_list_library_calls(self, netlink_mock, context_mock):
    """Tests if the initial library calls are made."""

    ukip.init_device_list()

    self.assertEqual(context_mock.call_count, 1)
    self.assertEqual(netlink_mock.call_count, 1)

  def test_init_device_list_exceptions(self):
    """Tests if exceptions were raised (ValueError and DeviceError)."""
    # TODO Implement this test.

  def test_init_device_list_device_count(self):
    """Tests if the number of devices is increased when iterating."""
    # TODO Implement this test.

  def test_init_device_list_invalid_pid_vid(self):
    """Tests if a ValueError is raised, when the VID/PID cannot be converted."""
    # TODO Implement this test.

  def test_init_device_list_runtimeerror(self):
    """Tests if the RuntimeError is thrown, when the thread failed to start."""
    # TODO Implement this test.

  def test_main_threading(self):
    """Tests if the thread was started."""
    # TODO Implement this test.

  def test_main_too_many_arguments(self):
    """Tests if no arguments were provided to main."""
    # TODO Implement this test.

  @mock.patch.object(pyudev.Monitor, 'from_netlink', autospec=True)
  def test_main_filter_by(self, netlink_mock):
    """Tests if the monitor filter_by was actually called."""

    monitor_mock = mock.MagicMock()
    pyudev.Monitor.from_netlink.return_value = monitor_mock
    monitor_mock.poll.side_effect = [self.pyudev_device, None]
    netlink_mock.return_value = monitor_mock

    ukip.main(['ukip.py'])

    calls = [mock.call(subsystem='input'), mock.call(subsystem='input')]
    monitor_mock.filter_by.assert_has_calls(calls)

  @mock.patch.object(builtins, 'open', autospec=True)
  def test_check_local_allowlist(self, open_mock):
    """Tests if the local allowlist check returns the allowlist on success."""

    open_mock.return_value.__enter__ = open_mock

    # Prepare a fake file, that looks similar to the actual file.
    open_mock.return_value.__iter__.return_value = iter([
        '# This is the config file\n', '# for UKIP.\n',
        '0x3784:0x3472 a,b,c\n'
    ])

    # Call with a PID and VID that will be found.
    allowlist = ukip.check_local_allowlist('0x3784', '0x3472')

    # If the PID and VID are found, the function returns the allowlist.
    self.assertEqual(
        allowlist,
        ukip.AllowlistConfigReturn(
            allowlist=['a', 'b', 'c'], device_present=True))

  @mock.patch.object(builtins, 'open', autospec=True)
  def test_check_local_allowlist_two_devices(self, open_mock):
    """Tests if the local allowlist with two devices, where one matches."""

    open_mock.return_value.__enter__ = open_mock

    # Prepare a fake file, that looks similar to the actual file.
    open_mock.return_value.__iter__.return_value = iter([
        '# This is the config file\n', '# for UKIP.\n',
        '0x1337:0x1234 x,y,z\n', '0x3784:0x3472 a,b,c\n'
    ])

    # Call with a PID and VID that will be found.
    allowlist = ukip.check_local_allowlist('0x3784', '0x3472')

    # If the PID and VID are found, the function returns the allowlist.
    self.assertEqual(
        allowlist,
        ukip.AllowlistConfigReturn(
            allowlist=['a', 'b', 'c'], device_present=True))

  @mock.patch.object(builtins, 'open', autospec=True)
  def test_check_local_allowlist_only_comments(self, open_mock):
    """Tests if the local allowlist check returns False when only comments."""

    open_mock.return_value.__enter__ = open_mock

    # Prepare a fake file, with only comments.
    open_mock.return_value.__iter__.return_value = iter([
        '# This is the config file\n', '# for UKIP.\n',
        '# One more comment line.\n'
    ])

    # Lookup for a PID and VID.
    allowlist = ukip.check_local_allowlist('0x3784', '0x3472')

    # If there are only comment in the config file, return False.
    self.assertEqual(
        allowlist,
        ukip.AllowlistConfigReturn(allowlist=[], device_present=False))

  @mock.patch.object(builtins, 'open', autospec=True)
  def test_check_local_allowlist_no_device(self, open_mock):
    """Tests if the allowlist check returns False when device not in file."""

    open_mock.return_value.__enter__ = open_mock

    open_mock.return_value.__iter__.return_value = iter([
        '# This is the config file\n', '# for UKIP.\n',
        '0x3784:0x3472 a,b,c\n'
    ])

    # Lookup for a PID and VID which are not in the config file.
    allowlist = ukip.check_local_allowlist('0x1234', '0x3472')

    # If the device cannot be found in the config file, return False.
    self.assertEqual(
        allowlist,
        ukip.AllowlistConfigReturn(allowlist=[], device_present=False))

  @mock.patch.object(builtins, 'open', autospec=True)
  def test_check_local_allowlist_key_val_parsing(self, open_mock):
    """Tests if the config file could be parsed into keys and values."""

    open_mock.return_value.__enter__ = open_mock
    open_mock.return_value.__iter__.return_value = iter([
        '# This is the config file\n', '# for UKIP.\n',
        'cannotparse\n'
    ])

    # Check if the exception was raised.
    self.assertRaises(ukip.AllowlistFileError, ukip.check_local_allowlist,
                      '0x1234', '0x3472')

  @mock.patch.object(builtins, 'open', autospec=True)
  def test_check_local_allowlist_device_parsing(self, open_mock):
    """Tests if the device in the config file can be parsed."""

    open_mock.return_value.__enter__ = open_mock
    open_mock.return_value.__iter__.return_value = iter([
        '# This is the config file\n', '# for UKIP.\n',
        '37843472 a,b,c\n'
    ])

    self.assertRaises(ukip.AllowlistFileError, ukip.check_local_allowlist,
                      '0x3784', '0x3472')

  @mock.patch.object(builtins, 'open', autospec=True)
  def test_check_local_allowlist_parsing(self, open_mock):
    """Tests if allowlist could be parsed from the config file."""

    open_mock.return_value.__enter__ = open_mock
    open_mock.return_value.__iter__.return_value = iter([
        '# This is the config file\n', '# for UKIP.\n',
        '0x3784:0x3472 cannotparse\n'
    ])

    # The device will be found, but the allowlist cannot be parsed.
    allowlist = ukip.check_local_allowlist('0x3784', '0x3472')

    # If the allowlist is a word, that is not 'any' or 'none', return False.
    self.assertEqual(
        allowlist,
        ukip.AllowlistConfigReturn(allowlist=[], device_present=False))

  @mock.patch.object(builtins, 'open', autospec=True)
  def test_check_local_allowlist_file_not_found(self, open_mock):
    """Tests if the config file could be found."""

    open_mock.side_effect = ukip.AllowlistFileError(
        'The config file /etc/ukip/allowlist could not be found: %s')

    self.assertRaises(ukip.AllowlistFileError, ukip.check_local_allowlist,
                      '0x3784', '0x3472')

  @mock.patch.object(builtins, 'open', autospec=True)
  def test_check_local_allowlist_empty_lines(self, open_mock):
    """Tests if the allowlist check returns False when only empty lines."""

    open_mock.return_value.__enter__ = open_mock

    # Prepare a fake file, with only empty lines.
    open_mock.return_value.__iter__.return_value = iter(
        ['\n', '    \n', '        \n'])

    # Lookup for a PID and VID.
    allowlist = ukip.check_local_allowlist('0x3784', '0x3472')

    # If there are only empty lines in the config file, return False.
    self.assertEqual(
        allowlist,
        ukip.AllowlistConfigReturn(allowlist=[], device_present=False))

  @mock.patch.object(builtins, 'open', autospec=True)
  def test_check_local_allowlist_allow_all(self, open_mock):
    """Tests if the allowlist check returns True for "allow all characters"."""

    open_mock.return_value.__enter__ = open_mock

    # Prepare a fake file, with only empty lines.
    open_mock.return_value.__iter__.return_value = iter([
        '0x1234:0x1337 any\n',
    ])

    # Lookup for a PID and VID.
    allowlist = ukip.check_local_allowlist('0x1234', '0x1337')

    # If all possible characters are allowed for a device, return an empty list
    # and True.
    self.assertEqual(
        allowlist,
        ukip.AllowlistConfigReturn(allowlist=[], device_present=True))

  @mock.patch.object(builtins, 'open', autospec=True)
  def test_check_local_allowlist_deny_all(self, open_mock):
    """Tests if the allowlist is an empty list when denying all characters."""

    open_mock.return_value.__enter__ = open_mock

    # Prepare a fake file, with only empty lines.
    open_mock.return_value.__iter__.return_value = iter([
        '0x1234:0x1337 none\n',
    ])

    # Lookup for a PID and VID.
    allowlist = ukip.check_local_allowlist('0x1234', '0x1337')

    # If no characters are allowed for the given device, return an empty list.
    self.assertEqual(
        allowlist,
        ukip.AllowlistConfigReturn(allowlist=[], device_present=False))

  def fill_test_ringbuffer_with_data(self):
    """A helper function to add times and trigger the hardening mode."""
    ukip.add_to_ring_buffer(self.event_device_path, 1555146977759524, 'a',
                            self.mock_pyusb_device)
    ukip.add_to_ring_buffer(self.event_device_path, 1555146977859525, 'b',
                            self.mock_pyusb_device)
    ukip.add_to_ring_buffer(self.event_device_path, 1555146977959526, 'c',
                            self.mock_pyusb_device)
    ukip.add_to_ring_buffer(self.event_device_path, 1555146977959527, 'd',
                            self.mock_pyusb_device)
    ukip.add_to_ring_buffer(self.event_device_path, 1555146977959528, 'e',
                            self.mock_pyusb_device)

  @mock.patch.object(gc, 'collect', wraps=gc.collect)
  @mock.patch.object(ukip, 'check_local_allowlist', autospec=True)
  @mock.patch.object(ukip, 'log', autospec=True)
  def test_enforce_hardening_mode_with_product(self, logging_mock,
                                               check_allowlist_mock, gc_mock):
    """Tests which logging message is emitted when device has a product set."""

    self.fill_test_ringbuffer_with_data()

    self.mock_pyusb_device.__iter__.return_value = iter([self.mock_usb_config])

    # Need a link, because after the function is run, the dicts are deleted.
    timings = ukip._event_devices_timings[self.event_device_path]

    # Return the allowlist from /etc/ukip/allowlist.
    check_allowlist_mock.return_value = ukip.AllowlistConfigReturn(
        allowlist=['a', 'b', 'c'], device_present=True)

    ukip.enforce_hardening_mode(self.mock_pyusb_device, self.event_device_path)

    check_allowlist_mock.assert_called_once_with(
        hex(self.mock_pyusb_device.idProduct),
        hex(self.mock_pyusb_device.idVendor))

    # Only 1 interface, so the range is 0.
    self.mock_pyusb_device.detach_kernel_driver.assert_called_once_with(0)

    logging_mock.warning.assert_called_with(
        '[UKIP] The device %s with the vendor id %s and the product id %s '
        'was blocked. The causing timings were: %s.',
        self.mock_pyusb_device.product, hex(self.mock_pyusb_device.idVendor),
        hex(self.mock_pyusb_device.idProduct), timings)

    # The error was not logged.
    self.assertFalse(logging_mock.error.called)

    # The dicts are deleted now.
    self.assertFalse(ukip._event_devices_timings)
    self.assertFalse(ukip._event_devices_keystrokes)

    # And the garbage collector ran.
    gc_mock.assert_called_once()

  @mock.patch.object(gc, 'collect', wraps=gc.collect)
  @mock.patch.object(ukip, 'check_local_allowlist', autospec=True)
  @mock.patch.object(ukip, 'log', autospec=True)
  def test_enforce_hardening_mode_no_product(self, logging_mock,
                                             check_allowlist_mock, gc_mock):
    """Tests which logging message is emitted when device has no product set."""

    self.fill_test_ringbuffer_with_data()

    self.mock_pyusb_device.__iter__.return_value = iter([self.mock_usb_config])
    self.mock_pyusb_device.product = None

    # Need a link, because after the function is run, the dicts are deleted.
    timings = ukip._event_devices_timings[self.event_device_path]

    # Return the allowlist from /etc/ukip/allowlist.
    check_allowlist_mock.return_value = ukip.AllowlistConfigReturn(
        allowlist=['a', 'b', 'c'], device_present=True)

    ukip.enforce_hardening_mode(self.mock_pyusb_device, self.event_device_path)

    check_allowlist_mock.assert_called_once_with(
        hex(self.mock_pyusb_device.idProduct),
        hex(self.mock_pyusb_device.idVendor))

    # Only 1 interface, so the range is 0.
    self.mock_pyusb_device.detach_kernel_driver.assert_called_once_with(0)

    logging_mock.warning.assert_called_with(
        '[UKIP] The device with the vendor id %s and the product id %s was '
        'blocked. The causing timings were: %s.',
        hex(self.mock_pyusb_device.idVendor),
        hex(self.mock_pyusb_device.idProduct), timings)

    self.assertFalse(logging_mock.error.called)

    # The dicts are deleted now.
    self.assertFalse(ukip._event_devices_timings)
    self.assertFalse(ukip._event_devices_keystrokes)

    # And the garbage collector ran.
    gc_mock.assert_called_once()

  @mock.patch.object(ukip, 'check_local_allowlist', autospec=True)
  @mock.patch.object(ukip, 'log', autospec=True)
  def test_enforce_hardening_mode_no_active_driver(self, logging_mock,
                                                   check_allowlist_mock):
    """Tests flow through function when no interface has an active driver."""

    self.fill_test_ringbuffer_with_data()

    self.mock_pyusb_device.__iter__.return_value = iter([self.mock_usb_config])
    self.mock_pyusb_device.is_kernel_driver_active.return_value = False

    # Return the allowlist from /etc/ukip/allowlist.
    check_allowlist_mock.return_value = ukip.AllowlistConfigReturn(
        allowlist=['a', 'b', 'c'], device_present=True)

    ukip.enforce_hardening_mode(self.mock_pyusb_device, self.event_device_path)

    check_allowlist_mock.assert_called_once_with(
        hex(self.mock_pyusb_device.idProduct),
        hex(self.mock_pyusb_device.idVendor))

    self.assertFalse(self.mock_pyusb_device.detach_kernel_driver.called)
    self.assertFalse(logging_mock.warning.called)
    self.assertFalse(logging_mock.error.called)

  @mock.patch.object(ukip, 'check_local_allowlist', autospec=True)
  @mock.patch.object(ukip, 'log', autospec=True)
  def test_enforce_hardening_mode_ioerror(self, logging_mock,
                                          check_allowlist_mock):
    """Tests IOError/log message for unbinding a driver from an interface."""

    self.fill_test_ringbuffer_with_data()

    log_message = ('There was an error in unbinding the interface for the USB '
                   'device %s: %s')
    exception_message = '[Errno 16] Device or resource busy'
    exception_object = IOError(exception_message)

    product_id = hex(self.mock_pyusb_device.idProduct)
    vendor_id = hex(self.mock_pyusb_device.idVendor)
    pid_and_vid = '%s:%s' % (product_id, vendor_id)

    self.mock_pyusb_device.__iter__.return_value = iter([self.mock_usb_config])
    self.mock_pyusb_device.detach_kernel_driver.side_effect = exception_object

    # Return the allowlist from /etc/ukip/allowlist.
    check_allowlist_mock.return_value = ukip.AllowlistConfigReturn(
        allowlist=['a', 'b', 'c'], device_present=True)

    ukip.enforce_hardening_mode(self.mock_pyusb_device, self.event_device_path)

    check_allowlist_mock.assert_called_once_with(
        hex(self.mock_pyusb_device.idProduct),
        hex(self.mock_pyusb_device.idVendor))

    logging_mock.warning.assert_called()

  @mock.patch.object(gc, 'collect', wraps=gc.collect)
  @mock.patch.object(ukip, 'check_local_allowlist', autospec=True)
  @mock.patch.object(ukip, 'log', autospec=True)
  def test_enforce_hardening_mode_multiple_interfaces_error(
      self, logging_mock, check_allowlist_mock, gc_mock):
    """Tests multiple interfaces, with one failing with an IOError."""

    self.fill_test_ringbuffer_with_data()

    log_message = ('There was an error in unbinding the interface for the USB '
                   'device %s: %s')
    exception_message = '[Errno 16] Device or resource busy'
    exception_object = IOError(exception_message)

    product_id = hex(self.mock_pyusb_device.idProduct)
    vendor_id = hex(self.mock_pyusb_device.idVendor)
    pid_and_vid = '%s:%s' % (product_id, vendor_id)

    self.mock_pyusb_device.__iter__.return_value = iter([self.mock_usb_config])
    self.mock_usb_config.bNumInterfaces = 2

    self.mock_pyusb_device.detach_kernel_driver.side_effect = [
        exception_object, mock.DEFAULT
    ]

    # Need a link, because after the function is run, the dicts are deleted.
    timings = ukip._event_devices_timings[self.event_device_path]

    # Return the allowlist from /etc/ukip/allowlist.
    check_allowlist_mock.return_value = ukip.AllowlistConfigReturn(
        allowlist=['a', 'b', 'c'], device_present=True)

    ukip.enforce_hardening_mode(self.mock_pyusb_device, self.event_device_path)

    check_allowlist_mock.assert_called_once_with(
        hex(self.mock_pyusb_device.idProduct),
        hex(self.mock_pyusb_device.idVendor))

    call = [
        mock.call(
            '[UKIP] The device %s with the vendor id %s and the product id '
            '%s was blocked. The causing timings were: %s.',
            self.mock_pyusb_device.product,
            hex(self.mock_pyusb_device.idVendor),
            hex(self.mock_pyusb_device.idProduct), timings)
    ]
    logging_mock.warning.assert_has_calls(call)

    # The dicts are deleted now.
    self.assertFalse(ukip._event_devices_timings)
    self.assertFalse(ukip._event_devices_keystrokes)

    # And the garbage collector ran.
    gc_mock.assert_called_once()

  @mock.patch.object(ukip, 'check_local_allowlist', autospec=True)
  @mock.patch.object(ukip, 'log', autospec=True)
  def test_enforce_hardening_mode_oserror(self, logging_mock,
                                          check_allowlist_mock):
    """Tests OSError/log message for unbinding a driver from an interface."""

    self.fill_test_ringbuffer_with_data()

    log_message = ('There was an error in unbinding the interface for the USB '
                   'device %s: %s')
    exception_message = 'access violation'
    exception_object = OSError(exception_message)

    product_id = hex(self.mock_pyusb_device.idProduct)
    vendor_id = hex(self.mock_pyusb_device.idVendor)
    pid_and_vid = '%s:%s' % (product_id, vendor_id)

    self.mock_pyusb_device.__iter__.return_value = iter([self.mock_usb_config])
    self.mock_pyusb_device.detach_kernel_driver.side_effect = exception_object

    # Return the allowlist from /etc/ukip/allowlist.
    check_allowlist_mock.return_value = ukip.AllowlistConfigReturn(
        allowlist=['a', 'b', 'c'], device_present=True)

    ukip.enforce_hardening_mode(self.mock_pyusb_device, self.event_device_path)

    check_allowlist_mock.assert_called_once_with(
        hex(self.mock_pyusb_device.idProduct),
        hex(self.mock_pyusb_device.idVendor))

    logging_mock.warning.assert_called()

  @mock.patch.object(ukip, 'check_local_allowlist', autospec=True)
  @mock.patch.object(ukip, 'log', autospec=True)
  def test_enforce_hardening_mode_valueerror(self, logging_mock,
                                             check_allowlist_mock):
    """Tests ValueError/log message for unbinding a driver from an interface."""

    self.fill_test_ringbuffer_with_data()

    log_message = ('There was an error in unbinding the interface for the USB '
                   'device %s: %s')
    exception_message = 'Invalid configuration'
    exception_object = ValueError(exception_message)

    product_id = hex(self.mock_pyusb_device.idProduct)
    vendor_id = hex(self.mock_pyusb_device.idVendor)
    pid_and_vid = '%s:%s' % (product_id, vendor_id)

    self.mock_pyusb_device.__iter__.return_value = iter([self.mock_usb_config])
    self.mock_pyusb_device.detach_kernel_driver.side_effect = exception_object

    # Return the allowlist from /etc/ukip/allowlist.
    check_allowlist_mock.return_value = ukip.AllowlistConfigReturn(
        allowlist=['a', 'b', 'c'], device_present=True)

    ukip.enforce_hardening_mode(self.mock_pyusb_device, self.event_device_path)

    check_allowlist_mock.assert_called_once_with(
        hex(self.mock_pyusb_device.idProduct),
        hex(self.mock_pyusb_device.idVendor))

    logging_mock.warning.assert_called()

  @mock.patch.object(ukip, 'check_local_allowlist', autospec=True)
  @mock.patch.object(ukip, 'log', autospec=True)
  def test_enforce_hardening_mode_usberror(self, logging_mock,
                                           check_allowlist_mock):
    """Tests USBError/log message for unbinding a driver from an interface."""

    self.fill_test_ringbuffer_with_data()

    log_message = ('There was an error in unbinding the interface for the USB '
                   'device %s: %s')
    exception_message = 'USBError Accessing Configurations'
    exception_object = usb.core.USBError(exception_message)

    product_id = hex(self.mock_pyusb_device.idProduct)
    vendor_id = hex(self.mock_pyusb_device.idVendor)
    pid_and_vid = '%s:%s' % (product_id, vendor_id)

    self.mock_pyusb_device.__iter__.return_value = iter([self.mock_usb_config])
    self.mock_pyusb_device.detach_kernel_driver.side_effect = exception_object

    # Return the allowlist from /etc/ukip/allowlist.
    check_allowlist_mock.return_value = ukip.AllowlistConfigReturn(
        allowlist=['a', 'b', 'c'], device_present=True)

    ukip.enforce_hardening_mode(self.mock_pyusb_device, self.event_device_path)

    check_allowlist_mock.assert_called_once_with(
        hex(self.mock_pyusb_device.idProduct),
        hex(self.mock_pyusb_device.idVendor))

    logging_mock.warning.assert_called()

  @mock.patch.object(gc, 'collect', wraps=gc.collect)
  @mock.patch.object(ukip, 'check_local_allowlist', autospec=True)
  @mock.patch.object(ukip, 'log', autospec=True)
  def test_enforce_hardening_mode_any_keyword(self, logging_mock,
                                              check_allowlist_mock, gc_mock):
    """Tests an early return if the any keyword is set in the allowlist."""

    self.fill_test_ringbuffer_with_data()

    self.mock_pyusb_device.__iter__.return_value = iter([self.mock_usb_config])

    # Device present and empty allowlist -> any keyword was set.
    check_allowlist_mock.return_value = ukip.AllowlistConfigReturn(
        allowlist=[], device_present=True)

    ukip.enforce_hardening_mode(self.mock_pyusb_device, self.event_device_path)

    check_allowlist_mock.assert_called_once_with(
        hex(self.mock_pyusb_device.idProduct),
        hex(self.mock_pyusb_device.idVendor))

    # Due to the early return, none of the followup functions are called.
    self.assertFalse(self.mock_pyusb_device.detach_kernel_driver.called)
    self.assertFalse(logging_mock.called)
    self.assertFalse(gc_mock.called)

  @mock.patch.object(gc, 'collect', wraps=gc.collect)
  @mock.patch.object(ukip, 'check_local_allowlist', autospec=True)
  @mock.patch.object(ukip, 'log', autospec=True)
  def test_enforce_hardening_mode_keystrokes_allowed(self, logging_mock,
                                                     check_allowlist_mock,
                                                     gc_mock):
    """Tests an early return if the typed keys are allowed in the allowlist."""

    # This sets the typed keys to [a,b,c,d,e]
    self.fill_test_ringbuffer_with_data()

    self.mock_pyusb_device.__iter__.return_value = iter([self.mock_usb_config])

    # Device present and allowlist set to typed characters.
    check_allowlist_mock.return_value = ukip.AllowlistConfigReturn(
        allowlist=['a', 'b', 'c', 'd', 'e'], device_present=True)

    ukip.enforce_hardening_mode(self.mock_pyusb_device, self.event_device_path)

    check_allowlist_mock.assert_called_once_with(
        hex(self.mock_pyusb_device.idProduct),
        hex(self.mock_pyusb_device.idVendor))

    # Due to the early return, none of the followup functions are called.
    self.assertFalse(self.mock_pyusb_device.detach_kernel_driver.called)
    self.assertFalse(logging_mock.called)
    self.assertFalse(gc_mock.called)

  @mock.patch.object(gc, 'collect', wraps=gc.collect)
  @mock.patch.object(ukip, 'check_local_allowlist', autospec=True)
  @mock.patch.object(ukip, 'log', autospec=True)
  def test_enforce_hardening_mode_keystrokes_allowed_subset(
      self, logging_mock, check_allowlist_mock, gc_mock):
    """Tests an early return with a subset of allowed keys."""

    ukip.add_to_ring_buffer(self.event_device_path, 1555146977759524, 'a',
                            self.mock_pyusb_device)
    ukip.add_to_ring_buffer(self.event_device_path, 1555146977859525, 'b',
                            self.mock_pyusb_device)
    ukip.add_to_ring_buffer(self.event_device_path, 1555146977959526, 'c',
                            self.mock_pyusb_device)

    self.mock_pyusb_device.__iter__.return_value = iter([self.mock_usb_config])

    # Device present and allowlist set to typed characters.
    check_allowlist_mock.return_value = ukip.AllowlistConfigReturn(
        allowlist=['a', 'b', 'c', 'd', 'e', 'f'], device_present=True)

    ukip.enforce_hardening_mode(self.mock_pyusb_device, self.event_device_path)

    check_allowlist_mock.assert_called_once_with(
        hex(self.mock_pyusb_device.idProduct),
        hex(self.mock_pyusb_device.idVendor))

    # Due to the early return, none of the followup functions are called.
    self.assertFalse(self.mock_pyusb_device.detach_kernel_driver.called)
    self.assertFalse(logging_mock.called)
    self.assertFalse(gc_mock.called)

  @mock.patch.object(gc, 'collect', wraps=gc.collect)
  @mock.patch.object(ukip, 'check_local_allowlist', autospec=True)
  @mock.patch.object(ukip, 'log', autospec=True)
  def test_enforce_hardening_mode_device_not_present(self, logging_mock,
                                                     check_allowlist_mock,
                                                     gc_mock):
    """Tests function flow when the device is not present in the allowlist."""

    self.fill_test_ringbuffer_with_data()

    self.mock_pyusb_device.__iter__.return_value = iter([self.mock_usb_config])

    # Need a link, because after the function is run, the dicts are deleted.
    timings = ukip._event_devices_timings[self.event_device_path]

    # Return the allowlist from /etc/ukip/allowlist.
    check_allowlist_mock.return_value = ukip.AllowlistConfigReturn(
        allowlist=[], device_present=False)

    ukip.enforce_hardening_mode(self.mock_pyusb_device, self.event_device_path)

    check_allowlist_mock.assert_called_once_with(
        hex(self.mock_pyusb_device.idProduct),
        hex(self.mock_pyusb_device.idVendor))

    # Only 1 interface, so the range is 0.
    self.mock_pyusb_device.detach_kernel_driver.assert_called_once_with(0)

    logging_mock.warning.assert_called_with(
        '[UKIP] The device %s with the vendor id %s and the product id %s '
        'was blocked. The causing timings were: %s.',
        self.mock_pyusb_device.product, hex(self.mock_pyusb_device.idVendor),
        hex(self.mock_pyusb_device.idProduct), timings)

    # The error was not logged.
    self.assertFalse(logging_mock.error.called)

    # The dicts are deleted now.
    self.assertFalse(ukip._event_devices_timings)
    self.assertFalse(ukip._event_devices_keystrokes)

    # And the garbage collector ran.
    gc_mock.assert_called_once()

  @mock.patch.object(gc, 'collect', wraps=gc.collect)
  @mock.patch.object(ukip, 'check_local_allowlist', autospec=True)
  @mock.patch.object(ukip, 'log', autospec=True)
  def test_enforce_hardening_mode_one_key_off(self, logging_mock,
                                              check_allowlist_mock, gc_mock):
    """Tests the hardening mode when one typed key is not allowed."""

    # This sets the typed keys to [a,b,c,d,e]
    self.fill_test_ringbuffer_with_data()

    self.mock_pyusb_device.__iter__.return_value = iter([self.mock_usb_config])

    # Need a link, because after the function is run, the dicts are deleted.
    timings = ukip._event_devices_timings[self.event_device_path]

    # Return the allowlist from /etc/ukip/allowlist. The 'e' from the typed
    # keys is not allowed.
    check_allowlist_mock.return_value = ukip.AllowlistConfigReturn(
        allowlist=['a', 'b', 'c', 'd', 'f'], device_present=False)

    ukip.enforce_hardening_mode(self.mock_pyusb_device, self.event_device_path)

    check_allowlist_mock.assert_called_once_with(
        hex(self.mock_pyusb_device.idProduct),
        hex(self.mock_pyusb_device.idVendor))

    # Only 1 interface, so the range is 0.
    self.mock_pyusb_device.detach_kernel_driver.assert_called_once_with(0)

    logging_mock.warning.assert_called_with(
        '[UKIP] The device %s with the vendor id %s and the product id %s '
        'was blocked. The causing timings were: %s.',
        self.mock_pyusb_device.product, hex(self.mock_pyusb_device.idVendor),
        hex(self.mock_pyusb_device.idProduct), timings)

    # The error was not logged.
    self.assertFalse(logging_mock.error.called)

    # The dicts are deleted now.
    self.assertFalse(ukip._event_devices_timings)
    self.assertFalse(ukip._event_devices_keystrokes)

    # And the garbage collector ran.
    gc_mock.assert_called_once()

  @mock.patch.object(ukip, 'log', autospec=True)
  @mock.patch.object(builtins, 'open')
  def test_load_keycodes_from_file(self, open_mock, logging_mock):
    """Tests if the keycode file returns the KeycodesReturn class."""

    handle = open_mock().__enter__.return_value

    keycode_file_content = [{
        'lowcodes': [{
            '1': 'ESC',
            '2': '1'
        }],
        'capscodes': [{
            '1': 'ESC',
            '2': '!'
        }]
    }]

    file_mock = mock.MagicMock(side_effect=keycode_file_content)
    json_mock = mock.patch('json.load', file_mock)

    with open_mock:
      with json_mock as json_load_mock:
        keycodes = ukip.load_keycodes_from_file()
        json_load_mock.assert_called_with(handle)

    self.assertEqual(keycodes.lower_codes, {1: 'ESC', 2: '1'})
    self.assertEqual(keycodes.capped_codes, {1: 'ESC', 2: '!'})
    logging_mock.assert_not_called()

  @mock.patch.object(ukip, 'log', autospec=True)
  @mock.patch.object(builtins, 'open')
  def test_load_keycodes_from_file_missing_keyword(self, open_mock,
                                                   logging_mock):
    """Tests the keycode file returns when a keyword is missing."""

    handle = open_mock().__enter__.return_value

    keycode_file_content = [{
        'not_low_codes': [{
            '1': 'ESC',
            '2': '1'
        }],
        'capscodes': [{
            '1': 'ESC',
            '2': '!'
        }]
    }]

    file_mock = mock.MagicMock(side_effect=keycode_file_content)
    json_mock = mock.patch('json.load', file_mock)

    with open_mock:
      with json_mock as json_load_mock:
        keycodes = ukip.load_keycodes_from_file()
        json_load_mock.assert_called_with(handle)

    # The lowcodes keyword is missing in the keycodes file.
    self.assertEqual(keycodes.lower_codes, {})
    self.assertEqual(keycodes.capped_codes, {})
    logging_mock.error.assert_called()

  @mock.patch.object(ukip, 'log', autospec=True)
  @mock.patch.object(json, 'load', autospec=True)
  @mock.patch.object(builtins, 'open', autospec=True)
  def test_load_keycodes_from_file_overflowerror(self, open_mock, json_mock,
                                                 logging_mock):
    """Tests if KeycodesFileError is raised on an OverflowError."""

    json_mock.side_effect = OverflowError
    self.assertRaises(ukip.KeycodesFileError, ukip.load_keycodes_from_file)
    open_mock.assert_called()
    json_mock.assert_called()
    logging_mock.assert_not_called()

  @mock.patch.object(ukip, 'log', autospec=True)
  @mock.patch.object(json, 'load', autospec=True)
  @mock.patch.object(builtins, 'open', autospec=True)
  def test_load_keycodes_from_file_valueerror(self, open_mock, json_mock,
                                              logging_mock):
    """Tests if KeycodesFileError is raised on a ValueError."""

    json_mock.side_effect = ValueError
    self.assertRaises(ukip.KeycodesFileError, ukip.load_keycodes_from_file)
    open_mock.assert_called()
    json_mock.assert_called()
    logging_mock.assert_not_called()

  @mock.patch.object(ukip, 'log', autospec=True)
  @mock.patch.object(json, 'load', autospec=True)
  @mock.patch.object(builtins, 'open', autospec=True)
  def test_load_keycodes_from_file_typeerror(self, open_mock, json_mock,
                                             logging_mock):
    """Tests if KeycodesFileError is raised on a TypeError."""

    json_mock.side_effect = TypeError
    self.assertRaises(ukip.KeycodesFileError, ukip.load_keycodes_from_file)
    open_mock.assert_called()
    json_mock.assert_called()
    logging_mock.assert_not_called()

  @mock.patch.object(ukip, 'log', autospec=True)
  @mock.patch.object(json, 'load', autospec=True)
  @mock.patch.object(builtins, 'open', autospec=True)
  def test_load_keycodes_from_file_not_found(self, open_mock, json_mock,
                                             logging_mock):
    """Tests if KeycodesFileError is raised on a FileNotFoundError."""

    json_mock.side_effect = FileNotFoundError
    self.assertRaises(ukip.KeycodesFileError, ukip.load_keycodes_from_file)
    open_mock.assert_called()
    json_mock.assert_called()
    logging_mock.assert_not_called()


if __name__ == '__main__':
  unittest.main()
