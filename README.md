# BEBA Software Switch

[![Build Status](https://travis-ci.org/beba-eu/beba-switch.svg?branch=master)](https://travis-ci.org/beba-eu/beba-switch)

This is an implementation of the BEBA Software Switch based on the [CPqD OpenFlow 1.3 softswitch][ofss13].

[BEBA is a European H2020 project][beba] on SDN data plane programmability. Our goal is to devise a data plane abstraction and prototype implementations for future-proof network devices capable to be repurposed with middlebox-type functions well beyond static packet forwarding, with a focus on stateful processing and packet generation.

A controller for this switch can be found at https://github.com/beba-eu/beba-ctrl

# Features in a nutshell

The BEBA Switch is an OpenFlow 1.3 switch extended with support for:
* Stateful packet forwarding based on the [OpenState API][openstate]
* Packet generation based on the [InSP API][insp]

Such extensions to OpenFlow 1.3 are implemented using the *OpenFlow Experimenter* framework. The API to control them is defined in [oflib-exp/ofl-exp-beba.h](oflib-exp/ofl-exp-beba.h).

Moreover, BEBA targets software accelleration. We improve the CPqD softswitch troughput while retaining the simplicity of the original CPqD code base.

# Getting Started

Similarly to the CPqD softswitch, the following components are available in this package:
* `ofdatapath`: the switch implementation
* `ofprotocol`: secure channel for connecting the switch to the controller
* `oflib`: a library for converting to/from 1.3 wire format
* `dpctl`: a tool for configuring the switch from the console

For more information on how to use these components please refer to the [original CPqD's documentation][ofss13]

## Building

Run the following commands in the `beba-switch` directory to build and install everything:

    $ ./boot.sh
    $ ./configure
    $ make
    $ sudo make install

## Running

Please refer to the [original CPqD's softswitch README][ofss13-readme]

# Contribute
Please submit your bug reports, fixes and suggestions as pull requests on
GitHub, or by contacting us directly.

# License
BEBA Software Switch is released under the BSD license (BSD-like for
code from the original Stanford switch).

[beba]: http://www.beba-project.eu/
[openstate]: http://openstate-sdn.org/pub/openstate-ccr.pdf
[insp]: http://conferences.sigcomm.org/sosr/2016/papers/sosr_paper42.pdf
[ofss13]: http://cpqd.github.io/ofsoftswitch13/
[ofss13-readme]: https://github.com/CPqD/ofsoftswitch13/blob/master/README.md
[compileubuntu14]: http://tocai.dia.uniroma3.it/compunet-wiki/index.php/Installing_and_setting_up_OpenFlow_tools
