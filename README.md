# Basic OpenFlow Software Switch (BOFUSS)

This is an [OpenFlow 1.3][ofp13] compatible user-space software switch implementation. The code is based on the [Ericsson TrafficLab 1.1 softswitch implementation][ericssonsw11], with changes in the forwarding plane to support
OpenFlow 1.3. 

### [A paper that describes the basic architecture, selected use cases and a few benchmarks is available on Arxiv](https://arxiv.org/abs/1901.06699). 
If you use the switch for academic purpuses, please consider refering to it.

## [Please read the FAQ before posting an issue](https://github.com/CPqD/ofsoftswitch13/wiki/Frequently-Asked-Questions)

Check the [Wiki](https://github.com/CPqD/ofsoftswitch13/wiki) for some resources that could possibly help you to modify the switch.  

**UPDATE**: A new experimental branch with contributions from the [BEBA EU Project][beba-eu] is available with lots of performance improvements and OpenFlow extensions. If you want to try the code checkout to the BEBA-EU branch.

```bash
$ git checkout remotes/origin/BEBA-EU
```

The following components are available in this package:
* `ofdatapath`: the switch implementation
* `ofprotocol`: secure channel for connecting the switch to the controller
* `oflib`: a library for converting to/from 1.3 wire format
* `dpctl`: a tool for configuring the switch from the console


# Getting Started

These instructions have been tested on Ubuntu 16.04. Other distributions or versions may need different steps. 

## Before building
The switch makes use of the NetBee library to parse packets, so we need to install it first.

1. Install the following packages:

    ```
    $ sudo apt-get install cmake libpcap-dev libxerces-c3.1 libxerces-c-dev libpcre3 libpcre3-dev flex bison pkg-config autoconf libtool libboost-dev
    ```

2. Clone and build netbee

    ```
    $ git clone https://github.com/netgroup-polito/netbee.git
    $ cd netbee/src
    $ cmake .
    $ make
    ```

3. Add the shared libraries built in `/nbeesrc/bin/` to your `/usr/local/lib` directory

    ```
    $ sudo cp ../bin/libn*.so /usr/local/lib
    ```

4. Run `ldconfig`

    ```
    $ sudo ldconfig
    ```

5. Put the contens of folder `nbeesrc/include` in the `/usr/include`

    ```
    $ sudo cp -R ../include/* /usr/include/
    ```

## Building
Run the following commands in the `ofsoftswitch13` directory to build and install everything:

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

For a complete list of commands and arguments, use the `--help` argument. Also, check the wiki for [Flow Mod examples](https://github.com/CPqD/ofsoftswitch13/wiki/Dpctl-Flow-Mod-Cases)

# Contribute
Please submit your bug reports, fixes and suggestions as pull requests on
GitHub, or by contacting us directly.

# License
OpenFlow 1.3 Software Switch is released under the BSD license (BSD-like for
code from the original Stanford switch).

# Acknowledgments

This project was supported by Ericsson Innovation Center in Brazil.
Formerly maintained by CPqD in technical collaboration with Ericsson Research.

[**List of Contributors**](https://github.com/CPqD/ofsoftswitch13/wiki/List-of-Contributors)

# Contact
E-mail: Eder Leao Fernandes (ederleaofernandes at gmail . com)

[ofp13]: https://www.opennetworking.org/images/stories/downloads/specification/openflow-spec-v1.3.0.pdf
[ericssonsw11]: https://github.com/TrafficLab/of11softswitch
[compileubuntu14]: http://tocai.dia.uniroma3.it/compunet-wiki/index.php/Installing_and_setting_up_OpenFlow_tools
[beba-eu]: http://www.beba-project.eu/ 
