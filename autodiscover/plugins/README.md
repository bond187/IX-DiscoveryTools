# Changes made to `unconstrained_dataflow.py` in order to process z-wave wifi packets, and some provisional changes to process zigbee protocol packsts.

1. Lines 34-36: import `dot11`, `dot15d4`, and `zigbee` from `scapy.layers`.
2. Line 102, in `Host.to_stix()`: last `elif` changed to also check for "Dot11" and "Dot14d4" protocol strings.
3. Line 275, in `PacketProcessor`: added "Dot11" and "Dot15d4" tuples to the list.
4. 334, in `PacketProcessor.get_pkt_info()`: added a try/except when setting `dst` and `src`.
5. Line 404, in `__main__`: be sure to set `infile` and `outfile` appropriately before running. It takes a cap/pcap file as input, and outputs a stix bundle `.json`.
