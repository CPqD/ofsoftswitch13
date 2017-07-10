#!/bin/bash

# Script to install on most recent versions of Ubuntu
# Tested on the LTS versions 14.04 and 16.04.
# Feel free to contribute to additional systems

UBUNTU_DEPS="cmake libpcap-dev libxerces-c3.1 libxerces-c-dev libpcre3 libpcre3-dev flex bison pkg-config autoconf libtool libboost-dev"

install_deps()
{
    if [ $(lsb_release -si) = "Ubuntu" ]; then
        sudo apt-get install $UBUNTU_DEPS
    fi
}

install_nbee()
{
    git clone https://github.com/netgroup-polito/netbee.git
    cd netbee/src
    cmake .
    make
    cd ..
    sudo cp bin/libn*.so /usr/local/lib
    sudo ldconfig
    sudo cp -R include/* /usr/include/
    cd ..
}

switch()
{
    ./boot.sh
    ./configure
    make
    sudo make install
}

install_deps
install_nbee
switch