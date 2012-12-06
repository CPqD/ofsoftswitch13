OpenFlow 1.3 TODO LIST
=============================
Please take a look on the list of new features added, ongoing work and to do items.   

B.11.1 Refactor capabilities negotiation
----------------------------------------

TODO

- Enable ’multipart’ requests (requests spanning multiple messages).

ONGOING


DONE

- Pack and unpack of new and modified messages.
- Rename ’stats’ framework into the ’multipart’ framework. 
- Move port list description to its own multipart request/reply.
- Create flexible property structure to express table capabilities.
- Add capabilities for table-miss flow entries.
- Add next-table (i.e. goto) capabilities
- Move table capabilities to its own multipart request/reply.

B.11.2 More flexible table miss support
-----------------------------------------

TODO


ONGOING

DONE

- Add capabilities to describe the table-miss flow entry (EXT-123). 
- Remove table-miss config flags (EXT-108).
- Define table-miss flow entry as the all wildcard, lowest priority flow entry (EXT-108).
- Mandate support of the table-miss flow entry in every table to process table-miss packets (EXT-108)
- Change table-miss default to drop packets (EXT-119).

B.11.3 IPv6 Extension Header handling support
----------------------------------------------

TODO

ONGOING

DONE

- Hop-by-hop IPv6 extension header is present.
- Router IPv6 extension header is present.
- Fragmentation IPv6 extension header is present.
- Destination options IPv6 extension headers is present.
- Authentication IPv6 extension header is present.
- Encrypted Security Payload IPv6 extension header is present.
- No Next Header IPv6 extension header is present.
- IPv6 extension headers out of preferred order.
- Unexpected IPv6 extension header encountered

B.11.4 Per flow meters
-----------------------

TODO

ONGOING

DONE
- Simple rate-limiter support (drop packets).
- Flexible meter framework based on per-flow meters and meter bands.
- Meter statistics, including per band statistics.
- Enable to attach meters flexibly to flow entries.

B.11.5 Per connection event filtering
--------------------------------------

TODO


ONGOING

- Set default filter value to match OpenFlow 1.2 behaviour.

DONE

- Add asynchronous message filter for each controller connection.
- Controller message to set/get the asynchronous message filter.
- Remove OFPC_INVALID_TTL_TO_CONTROLLER config flag.

B.11.6 Auxiliary connections
-----------------------------

TODO

- Enable switch to create auxiliary connections to the controller.
- Mandate that auxiliary connection can not exist when main connection is not alive.
- Add auxiliary-id to the protocol to disambiguate the type of connection.
- Enable auxiliary connection over UDP and DTLS.

ONGOING

DONE

B.11.7 MPLS BoS matching
--------------------------

TODO

ONGOING

DONE

- A new OXM field OXM_OF_MPLS_BOS has been added to match the Bottom 
of Stack bit (BoS) from the MPLS header (EXT-85)

B.11.8 Provider Backbone Bridging tagging
-------------------------------------------

TODO



ONGOING


DONE
- Push and Pop operation to add PBB header as a tag.
- New OXM field to match I-SID for the PBB header.

B.11.9 Rework tag order
------------------------

TODO



ONGOING


DONE

B.11.10 Tunnel-ID metadata
---------------------------
- Remove defined order of tags in packet from the specification.
- Tags are now always added in the outermost possible position.
- Action-list can add tags in arbitrary order.
- Tag order is predefined for tagging in the action-set.TODO

ONGOING

DONE

- New OXM Field to match tunnel-id.

Duration for stats
-------------------

TODO



ONGOING

DONE

- Duration for meter stats.
- Done for port, queue and group stats

Cookies in packet-in
----------------------

TODO

ONGOING

DONE

- Cookie field was added to the packet-in message (EXT-7). 
- This field takes its value from the flow the
sends the packet to the controller. If the packet was not sent by 
a flow, this field is set to 0xffffffffffffffff.

B.11.13 On demand flow counters
--------------------------------

TODO

ONGOING

DONE

- New flow-mod flags have been added to disable packet and byte 
counters on a per-flow basis. Disabling such counters may improve 
flow handling performance in the switch.
