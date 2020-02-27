#!/bin/bash
# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Replace those variables to fit your needs.
NEW_KEYSTROKE_WINDOW=5
NEW_ABNORMAL_TYPING=50000
# Set either MONITOR or HARDENING.
RUN_MODE=MONITOR

# For systemd it's important to know which Linux flavor.
DEBIAN=true

# Path to virtual environment (.ukip/ in the user's home).
VENV_PATH=$HOME'/.ukip/'


function info() {
  echo -e "[\e[94m*\e[0m]" "$@"
}

function error() {
  echo -e "[\e[91m!\e[0m]" "$@"
}

function success() {
  echo -e "[\e[92m+\e[0m]" "$@"
}

function fatal() {
  error "$@"
  exit 1
}

function install_virtual_env() {
  # Replace the shebang line.
  sed -i 's@#!/usr/bin/env python3@#!'$VENV_PATH'bin/python3@g' src/ukip.py

  # Install the needed virtual environemt.
  /usr/bin/env python3 -m venv $VENV_PATH

  # Activate the venv.
  source $VENV_PATH'bin/activate'

  # Install wheel before requirements.
  /usr/bin/env pip3 -q install wheel

  # Install the required packages.
  /usr/bin/env pip3 -q install -r requirements.txt

  success "Successfully prepared and installed the virtual environment."
}

function replace_variables() {
  sed -i 's/ABNORMAL_TYPING = [^0-9]*\([0-9]\+\)/ABNORMAL_TYPING = '$NEW_ABNORMAL_TYPING'/g' src/ukip.py
  sed -i 's/KEYSTROKE_WINDOW = [^0-9]*\([0-9]\+\)/KEYSTROKE_WINDOW = '$NEW_KEYSTROKE_WINDOW'/g' src/ukip.py
  sed -i 's/_UKIP_RUN_MODE = UKIP_AVAILABLE_MODES\.\(MONITOR\|HARDENING\)/_UKIP_RUN_MODE = UKIP_AVAILABLE_MODES\.'$RUN_MODE'/g' src/ukip.py


  success "Successfully replaced abnormal typing and keystroke window variables in UKIP."
  success "Successfully set the run mode for UKIP."
}

function prepare_metadata() {
  ALLOWLIST_FILE=/etc/ukip/allowlist
  KEYCODES_FILE=/etc/ukip/keycodes

  sudo mkdir /etc/ukip/

  sudo cp data/allowlist $ALLOWLIST_FILE
  sudo chmod 0755 $ALLOWLIST_FILE
  sudo chown root:root $ALLOWLIST_FILE

  sudo cp data/keycodes $KEYCODES_FILE
  sudo chmod 0755 $KEYCODES_FILE
  sudo chown root:root $KEYCODES_FILE

  success "Installed the allowlist and the keycodes file in /etc/ukip/."
}

function install_ukip() {
  UKIP_BINARY=/usr/sbin/ukip

  sudo cp src/ukip.py $UKIP_BINARY
  sudo chmod 0755 $UKIP_BINARY
  sudo chown root:root $UKIP_BINARY

  success "Installed UKIP in /usr/sbin/."
}

function install_systemd_service() {
  if $DEBIAN; then
    # For Debian based OSs.
    SYSTEMD_PATH=/lib/systemd/system/ukip.service
  else
    # For Fedora based OSs.
    SYSTEMD_PATH=/usr/lib/systemd/system/ukip.service
  fi

  sudo cp data/ukip.service $SYSTEMD_PATH
  sudo chmod 0644 $SYSTEMD_PATH
  sudo chown root:root $SYSTEMD_PATH

  sudo systemctl start ukip.service

  # The start and enabling sometimes race.
  sleep 1

  sudo systemctl enable ukip.service

  success "Installed and started systemd service."
}

info "Preparing and installing the virtual environment..."
install_virtual_env

info "Replacing keystroke window, abnormal typing speed and run mode..."
replace_variables

info "Preparing UKIP metadata..."
prepare_metadata

info "Installing UKIP..."
install_ukip

info "Installing and starting systemd service..."
install_systemd_service

success "UKIP is now installed and enabled on startup!"
