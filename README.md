# OpenFlow 1.3 Software Switch

This is an [OpenFlow 1.3][ofp13] compatible user-space software switch implementation. The code is based on the [Ericsson TrafficLab 1.1 softswitch
implementation][ericssonsw11], with changes in the forwarding plane to support
OpenFlow 1.3.

The following components are available in this package:
* `ofdatapath`: the switch implementation
* `ofprotocol`: secure channel for connecting the switch to the controller
* `oflib`: a library for converting to/from 1.3 wire format
* `dpctl`: a tool for configuring the switch from the console

# Getting Started

These instructions have been tested on Ubuntu 12.04. Other distributions or versions may need different steps.

## Before building
The switch makes use of the NetBee library to parse packets, so we need to install it first.

1. Install the following packages:

    ```
    $ sudo apt-get install cmake libpcap-dev libxerces-c2-dev libpcre3-dev flex bison pkg-config autoconf libtool libboost-dev
    ```

2. Download and unpack the source code from: http://www.nbee.org/download/nbeesrc-12-05-16.php

3. Create the build system

    ```
    $ cd nbeesrc/src
    $ cmake .
    ```

4. Compile

    ```
    $ make
    ```

5. Add the shared libraries built in `/nbeesrc/bin/` to your `/usr/local/lib` directory

    ```
    $ sudo cp ../bin/libn*.so /usr/local/lib
    ```

6. Run `ldconfig`

    ```
    $ sudo ldconfig
    ```

7. Put the contens of folder `nbeesrc/include` in the `/usr/include`

    ```
    $ sudo cp -R ../include/* /usr/include/
    ```

## Building
Run the following commands in the `of13softswitch` directory to build and install everything:

    $ ./boot.sh
    $ ./configure
    $ make
    $ sudo make install

## Running
1. Start the datapath:

    ```
    $ sudo udatapath/ofdatapath --datapath-id=<dpid> --interfaces=<if-list> ptcp:<port>
    ```

    This will start the datapath, with the given datapath ID, using the interaces listed. It will open a passive TCP connection on the given port. For a complete list of options, use the `--help` argument.

2. Start the secure channel, which will connect the datapath to the controller:

    ```
    $ secchan/ofprotocol tcp:<switch-host>:<switch-port> tcp:<ctrl-host>:<ctrl-port>
    ```

    This will open TCP connections to both the switch and the controller, relaying OpenFlow protocol messages between them. For a complete list of options, use the `--help` argument.

## Configuring
You can send requests to the switch using the `dpctl` utility.

* Check the flow statistics for table 0.

    ```
    $ utilities/dpctl tcp:<switch-host>:<switch-port> stats-flow table=0
    ```

* Install a flow to match IPv6 packets with extension headers hop by hop and destination and coming from port 1.

    ```
    $ utilities/dpctl tcp:<switch-host>:<switch-port> flow-mod table=0,cmd=add in_port=1,eth_type=0x86dd,ext_hdr=hop+dest apply:output=2
    ```

* Add a meter:

    ```
    $ utilities/dpctl tcp:<switch-host>:<switch-port> meter-mod cmd=add,meter=1 drop:rate=50
    ```

* Send flow to meter table

    ```
    $ utilities/dpctl tcp:<switch-host>:<switch-port> flow-mod table=0,cmd=add in_port=1 meter:1
    ```

For a complete list of commands and arguments, use the `--help` argument.

The `dpctl` utility has some limitations at the moment:
* No support for OXM masks
* No support for multipart messages
* Some set_field action fields are not present


# Contribute
Please submit your bug reports, fixes and suggestions as pull requests on
GitHub, or by contacting us directly.

# License
OpenFlow 1.3 Software Switch is released under the BSD license (BSD-like for
code from the original Stanford switch).

# Acknowledgments

This project is supported by Ericsson Innovation Center in Brazil.
Maintained by CPqD in technical collaboration with Ericsson Research.

**Contributions:**

Zoltán Lajos Kis, ofsoftswitch 1.1 implementation and guidance for OpenFlow spec related subjects.

Jean Tourrilhes, lots of critical memory bug fixes on table features.

Khai Nguyen Dinh and Thanh Le Dinh, contributions on meter features.

Rich Lane, added the right compiler linker.

yu-iwata, fixed flow deletion without matchin out_port.

Yuval Adler, bug fixes related to matching on vlan and ethertype.

Hiroyasu OHYAMA, correct URL of NetBee Library.

... 

*"Your name here" -- please, let us*
*know if we forgot to add your name to the list of contributors!*

# Contact
E-mail: Eder Leao Fernandes (ederlf@cpqd.com.br)

[ofp13]: https://www.opennetworking.org/images/stories/downloads/specification/openflow-spec-v1.3.0.pdf
[ericssonsw11]: https://github.com/TrafficLab/of11softswitch
