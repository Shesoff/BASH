#!/usr/bin/env bash

set -Eeuo pipefail

USERNAME=$1
PASSWORD=$2

for i in $(cat ip_hosts)
  do
  sshpass -p $PASSWORD ssh-copy-id -o StrictHostKeyChecking=no $USERNAME@$i
done
