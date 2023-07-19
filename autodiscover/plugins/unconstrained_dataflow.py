#Copyright 2021, Battelle Energy Alliance, LLC
## Logic:
# We want to be able to iterate through the entire pcap once (this will allow the speed to be O(n) for any operations we do).
# We need to be able to record what ips/port/protocol combinations have already been created/exist in a local manner (I don't trust the speed of the memorystore).
# Two-three modes may be required, one that summarized conversations, one that displays each packet, and one that summarizes all conversations as one or two objects.


## what data do we need to collect:
# start (time of first packet seen - if possible)
# end (time of last packet seen - if possible)
# is_active (should prob just not include)
# src_ref, dst_ref (should reference ipv4,ipv6, domain name, mac)
# src_port, dst_port
# protocols (if possible)
# src_byte_count
# dst_byte_count
# src_packets
# dst_packets
# ipfix?
# src_payload_ref 
# dst_payload_ref
# encapsulation(maybe)

# conversation will be identified by proto (TCP/UDP), dport, sport (need to be able to flip these), and highest level src/dst (need to be able to flip those) 
# lookup table for converstation, if it doesn't already exist, need to try to lookup hosts on either side.
# try by higest level proto and descend from there, if not found create.


from scapy.all import rdpcap, sniff
from scapy.utils import PcapReader
from scapy.layers.inet import IP, ICMP, UDP, TCP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, Dot3
from scapy.layers.dot11 import AKMSuite, Dot11CCMP, Dot11
from scapy.layers.dot15d4 import * #Dot15d4, dot15d4AddressField
from scapy.layers.zigbee import *
from inspect import getmembers
import sys
from pprint import pprint
from collections import Counter
from tqdm import tqdm
from autodiscover.util.helper import get_object_or_create
from autodiscover.util.loader import stix_loader
from uuid import uuid4, uuid5
from stix2 import Infrastructure, IPv4Address, IPv6Address, MACAddress, Relationship, NetworkTraffic
from datetime import datetime, timedelta
import logging


conf.dot15d4_protocol = "zigbee"

# from scapy import packet, 

class Host:
    # key represents whether this host is referenced as the src or dst in the packet.
    def __init__(self, pkt, top_addr_proto, src=True):

        addr_key = 'src' if src else 'dst'
        self.addrs = {}
        self.stix_addrs = {}
        self.top_addr_proto = top_addr_proto
        # self.top_addr = f'{top_addr_proto}-{addr_key}'
        self.top_addr = None
        for _, proto in PacketProcessor.src_dst_protos:
            try:
                # self.addrs[proto] = pkt[f'{proto}_{addr_key}']
                self.addrs[pkt[f'{proto}_{addr_key}']] = proto
                if self.top_addr is None:
                    self.top_addr = pkt[f'{proto}_{addr_key}']

                

            except KeyError:
                pass

    def get_addrs(self):
        return self.addrs.keys() 

    def to_stix(self):
        print("h.to_stix called")
        l = []
        infra = Infrastructure(name=self.top_addr)
        l.append(infra)
        for addr, proto in self.addrs.items():
            if proto == 'IPv4':
                ipv4 = IPv4Address(value=addr)
                self.stix_addrs[addr] = ipv4
                l.append(ipv4)
                rel = Relationship(source_ref=infra, target_ref=ipv4,  relationship_type='has')
                l.append(rel)
            elif proto == 'IPv6':
                ipv6 = IPv6Address(value=addr)
                self.stix_addrs[addr] = ipv6
                l.append(ipv6)
                rel = Relationship(source_ref=infra, target_ref=ipv6,  relationship_type='has')
                l.append(rel)
            elif proto == 'MAC':
                mac = MACAddress(value=addr)
                self.stix_addrs[addr] = mac
                l.append(mac)
                rel = Relationship(source_ref=infra, target_ref=mac,  relationship_type='has')
                l.append(rel)
            elif proto == 'Dot3' or proto == 'Dot11' or proto == 'Dot15d4':
                mac = MACAddress(value=addr)
                self.stix_addrs[addr] = mac
                print("stix_addrs has been set: {}".format(self.stix_addrs[addr]))
                l.append(mac)
                rel = Relationship(source_ref=infra, target_ref=mac,  relationship_type='has')
                l.append(rel)

        return l

class HostHolder:
    def __init__(self):
        self.d = {}

    def add_hosts(self, pkt, top_addr_proto):
        # we need to store the addresses here
        h_src = None
        h_dst = None

        _h_src = Host(pkt, top_addr_proto)
        for addr in _h_src.get_addrs():
            if addr in self.d:
                # Currently causing badness with external ips have the routers mac.
                if set(_h_src.get_addrs()) != set(self.d[addr].get_addrs()):
                    self.d[addr].addrs.update(_h_src.addrs)
                h_src = self.d[addr]
                break

        if h_src is None:
            h_src = _h_src
            for addr in h_src.get_addrs():
                self.d[addr] = h_src

        _h_dst = Host(pkt, top_addr_proto, src=False)
        for addr in _h_dst.get_addrs():
            if addr in self.d:
                if set(_h_dst.get_addrs()) != set(self.d[addr].get_addrs()):
                    self.d[addr].addrs.update(_h_dst.addrs)
                h_dst = self.d[addr]
                break
            
        if h_dst is None:
            h_dst = _h_dst
            for addr in h_dst.get_addrs():
                self.d[addr] = h_dst


        return h_src, h_dst

    def to_stix(self):
        stix_objs = []
        reduced_hosts = set(self.d.values())
        for host in reduced_hosts:
            stix_objs.extend(host.to_stix())
        return stix_objs


class ConversationHolder:
    def __init__(self, host_holder):
        self.hh = host_holder
        self.lookup_dict = {}

    #def add_pkt(self, port_proto, src_port, dst_port, src_dst_proto, src_address, dst_address, pkt)

    def add_pkt(self, port_proto, src_dst_proto, pkt):
        #print("(from add_pkt) Port proto: {}".format(port_proto))
        # This is ugly...
        # key = (f"{port_proto}-{pkt[f'{port_proto}_sport']}-{pkt[f'{port_proto}_dport']}-"
        # "{src_dst_proto}-{pkt[f'{src_dst_proto}_src']}-{pkt[f'{src_dst_proto}_dst']}")
        # rev_key = (f"{port_proto}-{pkt[f'{port_proto}_dport']}-{pkt[f'{port_proto}_sport']}-"
        # "{src_dst_proto}-{pkt[f'{src_dst_proto}_dst']}-{pkt[f'{src_dst_proto}_src']}")

        if port_proto is not None:
            key = (port_proto, pkt[f'{port_proto}_sport'], pkt[f'{port_proto}_dport'],
            src_dst_proto, pkt[f'{src_dst_proto}_src'], pkt[f'{src_dst_proto}_dst'])
            
            rev_key = (port_proto, pkt[f'{port_proto}_dport'], pkt[f'{port_proto}_sport'],
            src_dst_proto, pkt[f'{src_dst_proto}_dst'], pkt[f'{src_dst_proto}_src'])

        else:
            key = (None, None, None,
            src_dst_proto, pkt[f'{src_dst_proto}_src'], pkt[f'{src_dst_proto}_dst'])
            
            rev_key = (None, None, None,
            src_dst_proto, pkt[f'{src_dst_proto}_dst'], pkt[f'{src_dst_proto}_src'])

        if key in self.lookup_dict:
            self.add_to_conv(key, pkt)
        elif rev_key in self.lookup_dict:
            self.add_to_conv(rev_key, pkt, rev=True)
        else:
            self.make_conversation(key, pkt, port_proto, src_dst_proto)

    def add_to_conv(self, key, pkt, rev=False):
        if pkt['arr_time'] < self.lookup_dict[key]['start']:
            self.lookup_dict[key]['start'] = pkt['arr_time']
        if pkt['arr_time'] > self.lookup_dict[key]['end']:
            self.lookup_dict[key]['end'] = pkt['arr_time']

        self.lookup_dict[key]['protocols'].union(pkt['protocols'])

        if rev == True:
            self.lookup_dict[key]['dst_byte_count'] += pkt['size']
            self.lookup_dict[key]['dst_packets'] += 1
        else:
            self.lookup_dict[key]['src_byte_count'] += pkt['size']
            self.lookup_dict[key]['src_packets'] += 1
        # print(self.lookup_dict[key])


    def make_conversation(self, key, pkt, p_proto, sd_proto):
        #print("Packet type: {}".format(type(pkt)))
        #for key, value in pkt.items():
            #print(key, " : ", value, "(", type(value), ")")
        # start (time of first packet seen - if possible)
        # end (time of last packet seen - if possible)
        # is_active (should prob just not include)
        # src_ref, dst_ref (should reference ipv4,ipv6, domain name, mac)
        # src_port, dst_port
        # protocols (if possible)
        # src_byte_count
        # dst_byte_count
        # src_packets
        # dst_packets
        # ipfix?
        # src_payload_ref 
        # dst_payload_ref
        # encapsulation(maybe)
        src_object, dst_object = self.hh.add_hosts(pkt, sd_proto)
        addr_proto = pkt['addr_proto']
        print("addr_proto = {}".format(addr_proto))
        self.lookup_dict[key] = {
            'start': pkt['arr_time'],
            # the stix2 library refuses to have converstation in which end == start, however in 1 packet converstations that occurs... So we do hacky stuff
            'end': pkt['arr_time'] + timedelta(microseconds=1),
            'is_active': False,
            'src_ref': src_object,
            'dst_ref': dst_object,
            'src_addr' : pkt[f'{addr_proto}_src'],
            'dst_addr' : pkt[f'{addr_proto}_dst'],
            'src_port': None if p_proto is None else pkt[f'{p_proto}_sport'],
            'dst_port': None if p_proto is None else pkt[f'{p_proto}_dport'],
            'protocols': pkt['protocols'],
            'src_byte_count': pkt['size'],
            'dst_byte_count':0,
            'src_packets': 1,
            'addr_proto': addr_proto,
            'dst_packets': 0
            # 'src_object':1,
            # 'dst_object':1
        }
        #self.lookup_dict[key]['addr_proto'] = addr_proto
        print("This is addr_proto from make_convo: {}".format(self.lookup_dict[key]["addr_proto"]))
        #   'IPv4_dst': '8.8.8.8', 'IPv4_src': '192.168.60.20', 'UDP_dport': 53, 'UDP_sport': 63000, 'MAC_dst': 'b4:fb:e4:8d:fb:76', 'MAC_src': 'cc:48:3a:5a:b3:3a'}

    def to_stix(self):
        l = []
        print("From to_stix:")
        for key, conversation in self.lookup_dict.items():
            print("key: ", key, "Convo: ", conversation)
            try:
                addr_proto = conversation.pop('addr_proto')
            #except KeyError:
                #addr_proto = "Dot11"
                if addr_proto not in conversation['src_ref'].stix_addrs: 
                    logging.warning(f"Proto not in object: {conversation['src_ref'].stix_addrs}")
                if addr_proto not in conversation['dst_ref'].stix_addrs: 
                     logging.warning(f"Proto not in object: {conversation['dst_ref'].stix_addrs}")
                conversation['src_ref'] = conversation['src_ref'].stix_addrs[conversation.pop('src_addr')]
                conversation['dst_ref'] = conversation['dst_ref'].stix_addrs[conversation.pop('dst_addr')]
                print("Found them: {}, {}".format(addr_proto, conversation['src_ref']))
                #REMOVE CUSTOM
                netraffic = NetworkTraffic(**conversation, allow_custom=True)
                src_rel = Relationship(source_ref=conversation['src_ref'], target_ref=netraffic, relationship_type='communicates-with')
                dst_rel = Relationship(source_ref=netraffic, target_ref=conversation['dst_ref'], relationship_type='communicates-with')
                l.extend([netraffic, src_rel, dst_rel])
            except:
                continue
            return l

class PacketProcessor:
    # The tuple exists for display purposes, might be better to just do it later on
    src_dst_protos = [(IPv6, 'IPv6'), (IP, 'IPv4'), (Ether, 'MAC'), (Dot3, 'MAC'), 
                       (Dot11, 'Dot11'), (Dot15d4, 'Dot15d4')]
    # This one is just to we're not at the mercy of others tostrings
    port_protos = [(TCP, 'TCP'), (UDP, 'UDP')]
    def __init__(self, args, stix_loader, pcap=None):
        self.args = args
        self.sl = stix_loader

        self.hh = HostHolder()
        self.ch = ConversationHolder(self.hh)
        if pcap is not None:
            self.open_pcap(pcap)


    @staticmethod
    def get_numbered_protocols(packet):
        counter = 0
        yield counter, packet.name
        while packet.payload:
            packet = packet.payload
            counter += 1
            yield counter, packet.name

    @staticmethod        
    def get_protocols(packet):
        yield packet.name
        print(packet)
        while packet.payload:
            packet = packet.payload
            yield packet.name

    @staticmethod
    def get_clean_protocols(packet):
        for proto in PacketProcessor.get_protocols(packet):
            if proto not in ['Raw', 'Padding']:
                yield proto

    def get_pkt_info(self, pkt):
        print("----------------------NEW PACKET------------------------")
        print(pkt)
        d = {}
        d['size'] = len(pkt)
        d['arr_time'] = datetime.fromtimestamp(pkt.time) 
        d['protocols'] = set(self.get_clean_protocols(pkt))
        top_sd_proto = None
        top_p_proto = None
        #for zigbee, nothing is being captured besides the protocol type
        print(pkt)
        for src_dst_proto in self.src_dst_protos:
            sd_proto, sd_proto_name = src_dst_proto
            print("Testing for sd_proto: {}, sd_proto_name: {}".format(sd_proto, sd_proto_name))
            print(sd_proto, sd_proto_name)
            #trying make sure we don't duplicate a single system for each address type
            if sd_proto in pkt:
                print("{} found in packet!!".format(sd_proto))
                if top_sd_proto is None:
                    top_sd_proto = sd_proto_name
                    print("top_sd_proto is now {}".format(top_sd_proto))

                #---- ZigBee / 802.15.4----
                if sd_proto_name == "Dot15d4":
                    try:
                        d[f'{sd_proto_name}_dst'] = pkt.dest_addr #ZigBee 802.
                        d[f'{sd_proto_name}_src'] = pkt.src_addr
                        print("Recorded source address: {}".format(d[f'{sd_proto_name}_src']))
                    except:
                        d[f'{sd_proto_name}_dst'] = 0x0002 # There is at least one packet that can't be parsed. Need to deal with it in a better way.
                        d[f'{sd_proto_name}_src'] = 0x0002

                #---- WiFi / 802.11
                elif sd_proto_name == "Dot11":
                    d[f'{sd_proto_name}_dst'] = pkt[sd_proto].addr1
                    d[f'{sd_proto_name}_src'] = pkt[sd_proto].addr2

                #---- Ethernet / 802.3
                else:
                    d[f'{sd_proto_name}_dst'] = pkt[sd_proto].dst
                    d[f'{sd_proto_name}_src'] = pkt[sd_proto].src

            
                # may want to remove this later
                print("after the except")
                d['addr_proto'] = top_sd_proto
                for port_proto in self.port_protos:
                    p_proto, p_proto_name = port_proto
                    if p_proto in pkt:
                        if top_p_proto is None:
                            top_p_proto = p_proto_name

                        d[f'{p_proto_name}_dport'] = pkt[p_proto].dport
                        d[f'{p_proto_name}_sport'] = pkt[p_proto].sport

        print("All packet info retrieved: ")
        for key, value in d.items():
            print(key, ":", value)


        if ('IPv6_src' in d or 'IPv4_src' in d) and ('addr_proto' in d and d['addr_proto'] == 'MAC'):
            logging.warning(f'MAC is top proto when it shouldn\'t be : {d} {pkt.summary()}')


        if 'addr_proto' not in d:
            logging.warning(f'Packet has no address protocol: {d} {pkt.summary()}')

        self.ch.add_pkt(top_p_proto, top_sd_proto, d)

        print("-----------------------DONE--------------------------------")

        return d


    def open_pcap(self, path):
        # The below (will speedup) disables any sort of processing past TCP/UDP, keep protocol list clean as well, will need to be disabled if we wish to get more in-depth info
        # Ether.payload_guess = [({"type": 0x800}, IP)]
        # IP.payload_guess = [({"frag": 0, "proto": 0x11}, UDP), ({"frag": 0, "proto": 0x6}, TCP)]
        # TCP.payload_guess = []
        # UDP.payload_guess = []
        self.packets = PcapReader(path)
        #for pkt in self.packets:
            #print(pkt)

    def run(self):
        # print(packets.summary())
        # l = []
        count = 0
        for packet in tqdm(self.packets):
            #try:
            count += 1
            #if count % 2 == 0:
                #continue
                #print("even")
            #else:
            #print(count)
            self.get_pkt_info(packet)
            self.sl.merge(self.to_stix())
            print("Count: {}".format(count))

    def to_stix(self):
        objs = []
        #print("At hh.to_stix()")
        objs.extend(self.hh.to_stix())
        #print("Survived hh.to_stix()")
        try:
            objs.extend(self.ch.to_stix())
            return objs
        except TypeError:
            print("Can't extend objs (likely empty)")
            return objs
        #objs.extend()


        
if __name__ == "__main__":
    in_file = '/home/bb/Downloads/Zer0Trust-2G.pcap-01.cap'#'/home/bb/Downloads/1st-try_100.pcap'
    out_file = "2g.json"
    class dc:
        pass
    
    args = dc()
    sl = stix_loader()
    
    packetprocessor = PacketProcessor(args, sl, pcap=in_file)
    packetprocessor.run()
    #print(packetprocessor.to_stix())
    sl.write_out(out_file)
    # pprint(Counter(loop_data(p)))


