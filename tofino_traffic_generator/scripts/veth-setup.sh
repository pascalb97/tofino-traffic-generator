#! /usr/bin/env bash

function add_veth {
    intf=$1
    peer=$2
    ip link add name $intf type veth peer name $peer
    ip link set dev $intf up
    ip link set dev $peer up
    ip link set $intf mtu 9500
    ip link set $peer mtu 9500
    sysctl net.ipv6.conf.${intf}.disable_ipv6=1 2>&1 > /dev/null
    sysctl net.ipv6.conf.${peer}.disable_ipv6=1 2>&1 > /dev/null
}

veth_file=/tmp/veth

function add_veth_ports {
    count=$1
    rm -f $veth_file
    for idx in $(seq 0 $(( $count - 1 ))) ; do
        intf="veth$(($idx * 2))"
        peer="veth$(($idx * 2 + 1))"
        if ! ip link show $intf &> /dev/null; then
            add_veth $intf $peer
            echo $intf
            echo $intf >> /tmp/veth
        fi
    done
}


if [[ "$UID" != "0" ]]; then
        echo $(exec sudo $0 "$@")
else
        add_veth_ports $1
fi
