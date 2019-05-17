#!/usr/bin/env bash

while true; do

  /usr/bin/timeout 30s /usr/bin/tcpproxy 0 31337 0 3306 >> /var/log/tcpproxy.log 2>&1

done
