#! /usr/bin/env bash

set -e

tar xvf /tmp/bf-sde-9.9.1.tgz -C ~vagrant
cd ~vagrant/bf-sde-9.9.1/p4studio
sudo ./install-p4studio-dependencies.sh
./p4studio profile apply ~vagrant/dependencies/behavioural.yaml

chown vagrant:vagrant /home/vagrant/bf-sde-9.9.1 -R
