#!/usr/bin/env bash

cd  $( dirname "${BASH_SOURCE[0]}" )
cp elastic /etc/ufw/applications.d/
cp kibana /etc/ufw/applications.d/
ufw app update all
