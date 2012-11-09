OpenFlow 1.3 Software Switch
============================

This is an [OpenFlow 1.3][ofp13] compatible user-space software switch
implementation. The code is based on the [Ericsson TrafficLab 1.1 softswitch
implementation][ericssonsw11], with changes in the forwarding plane to support
OpenFlow 1.3.

The following components are available in the release:
  - ofdatapath: the switch implementation
  - ofprotocol: secure channel for connecting the switch to the controller
  - oflib:      a library for converting to/from 1.3 wire format
  - dpctl:      a tool for configuring the switch from the console


Getting Started
===============

Pre-Building
------------

The software switch makes use of the Netbee library to parse packets, therefore library files needed to build  
the switch.

To compile Netbee on your system your  
system you need to install the following packages:

    $ sudo apt-get install cmake libpcap-dev libxerces-c2-dev libpcre3-dev flex bison  

Download the source code on http://www.nbee.org/download/nbeesrc-12-05-16.php
    
Create the build system  
  
    $ cd nbeesrc/src  
    $ cmake.

Compile  
    
    $ make

Add the shared libraries built in `/nbeesrc/bin/` to your `/usr/local/lib` directory.  

    $ sudo cp nbeesrc/bin/libn*.so /usr/local/lib

Run `ldconfig`:

    $ sudo ldconfig

Put the folder `nbeesrc/include` in the `/usr/include`:

    $ sudo cp -R nbeesrc/include /usr/include


Building
--------

To build, run the following commands in the `of12softswitch` directory:

    $ ./boot.sh
    $ ./configure
    $ make
    $ sudo make install
    
Running
-------

Start the datapath:

    $ sudo udatapath/ofdatapath --datapath-id=<dpid> --interfaces=<if-list> ptcp:<port>

This will start the datapath, with the given datapath id, and interace list,
opening a passive tcp connection on the given port. For a complete list of
options, use the `--help` argument.

Start the secure channel:

    $ secchan/ofprotocol tcp:<switch-host>:<switch-port> tcp:<ctrl-host>:<ctrl-port>

This will open TCP connections to both the switch and the controller, relaying
OpenFlow protocol messages between the two. For a complete list of options,
use the `--help` argument.

You can send requests to the switch using the `dpctl` utility:

    $ cd utilities
    $ ./dpctl tcp:<switch-host>:<switch-port> stats-flow table=0

For a complete list of commands and arguments, use the `--help` argument.

Contribute
==========

Please submit your bug reports, fixes and suggestions as pull requests on
github, or by contacting us directly.

License
=======

OpenFlow 1.3 Software Switch is released under the BSD license (BSD-like for
code from the original Stanford switch).

Contact
=======

E-mail: Eder Leao Fernandes (ederlf@cpqd.com.br)

[ofp13]: https://www.opennetworking.org/images/stories/downloads/specification/openflow-spec-v1.3.0.pdf
[ericssonsw11]: https://github.com/TrafficLab/of11softswitch


