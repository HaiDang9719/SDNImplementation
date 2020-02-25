from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu.lib.packet import ether_types
from ryu.lib import mac, ip
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
from ryu.topology import event

from collections import defaultdict
from operator import itemgetter

import os
import random
import time

# Cisco Reference bandwidth = 1 Gbps
REFERENCE_BW = 10000000

DEFAULT_BW = 10000000

MAX_PATHS = 2

class ProjectController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ProjectController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.topology_api_app = self
        self.datapath_list = {}
        self.arp_table = {}
        self.switches = []
        self.hosts = {}
        self.multipath_group_ids = {}
        self.group_ids = []
        self.adjacency = defaultdict(dict)
        self.bandwidths = defaultdict(lambda: defaultdict(lambda: DEFAULT_BW))

    def get_paths(self, src, dst):
        '''
        Get all paths from src to dst using DFS algorithm    
        '''
        if src == dst:
            # host target is on the same switch
            return [[src]]
        paths = []
        stack = [(src, [src])]
        while stack:
            (node, path) = stack.pop()
            for next in set(self.adjacency[node].keys()) - set(path):
                if next is dst:
                    paths.append(path + [next])
                else:
                    stack.append((next, path + [next]))
        print ("Available paths from ", src, " to ", dst, " : ", paths)
        return paths

    def get_link_cost(self, s1, s2):
        '''
        Get the link cost between two switches 
        '''
        e1 = self.adjacency[s1][s2]
        e2 = self.adjacency[s2][s1]
        bl = min(self.bandwidths[s1][e1], self.bandwidths[s2][e2])
        ew = REFERENCE_BW/bl
        return ew

    def get_path_cost(self, path):
        '''
        Get the path cost
        '''
        cost = 0
        for i in range(len(path) - 1):
            cost += self.get_link_cost(path[i], path[i+1])
        return cost

    def get_optimal_paths(self, src, dst):
        '''
        Get the n-most optimal paths according to MAX_PATHS
        '''
        paths = self.get_paths(src, dst)
        paths_count = len(paths) if len(
            paths) < MAX_PATHS else MAX_PATHS
        return sorted(paths, key=lambda x: self.get_path_cost(x))[0:(paths_count)]

    def add_ports_to_paths(self, paths, first_port, last_port):
        '''
        Add the ports that connects the switches for all paths
        '''
        paths_p = []
        for path in paths:
            p = {}
            in_port = first_port
            for s1, s2 in zip(path[:-1], path[1:]):
                out_port = self.adjacency[s1][s2]
                p[s1] = (in_port, out_port)
                in_port = self.adjacency[s2][s1]
            p[path[-1]] = (in_port, last_port)
            paths_p.append(p)
        return paths_p

    def generate_openflow_gid(self):
        '''
        Returns a random OpenFlow group id
        '''
        n = random.randint(0, 2**32)
        while n in self.group_ids:
            n = random.randint(0, 2**32)
        return n


    def install_paths(self, src, first_port, dst, last_port, ip_src, ip_dst):
        computation_start = time.time()
        paths = self.get_optimal_paths(src, dst)
        pw = []
        for path in paths:
            pw.append(self.get_path_cost(path))
            print path, "cost = ", pw[len(pw) - 1]
        sum_of_pw = sum(pw) * 1.0
        paths_with_ports = self.add_ports_to_paths(paths, first_port, last_port)
        switches_in_paths = set().union(*paths)

        for node in switches_in_paths:

            dp = self.datapath_list[node]
            ofp = dp.ofproto
            ofp_parser = dp.ofproto_parser

            ports = defaultdict(list)
            actions = []
            i = 0

            for path in paths_with_ports:
                if node in path:
                    in_port = path[node][0]
                    out_port = path[node][1]
                    if (out_port, pw[i]) not in ports[in_port]:
                        ports[in_port].append((out_port, pw[i]))
                i += 1

            for in_port in ports:

                match_ip = ofp_parser.OFPMatch(
                    eth_type=0x0800, 
                    ipv4_src=ip_src, 
                    ipv4_dst=ip_dst
                )
                match_arp = ofp_parser.OFPMatch(
                    eth_type=0x0806, 
                    arp_spa=ip_src, 
                    arp_tpa=ip_dst
                )

                out_ports = ports[in_port]
                # print out_ports 

                if len(out_ports) > 1:
                    group_id = None
                    group_new = False

                    if (node, src, dst) not in self.multipath_group_ids:
                        group_new = True
                        self.multipath_group_ids[
                            node, src, dst] = self.generate_openflow_gid()
                    group_id = self.multipath_group_ids[node, src, dst]

                    buckets = []
                    # print "node at ",node," out ports : ",out_ports
                    for port, weight in out_ports:
                        bucket_weight = int(round((1 - weight/sum_of_pw) * 10))
                        bucket_action = [ofp_parser.OFPActionOutput(port)]
                        buckets.append(
                            ofp_parser.OFPBucket(
                                weight=bucket_weight,
                                watch_port=port,
                                watch_group=ofp.OFPG_ANY,
                                actions=bucket_action
                            )
                        )

                    if group_new:
                        req = ofp_parser.OFPGroupMod(
                            dp, ofp.OFPGC_ADD, ofp.OFPGT_SELECT, group_id,
                            buckets
                        )
                        dp.send_msg(req)
                    else:
                        req = ofp_parser.OFPGroupMod(
                            dp, ofp.OFPGC_MODIFY, ofp.OFPGT_SELECT,
                            group_id, buckets)
                        dp.send_msg(req)

                    actions = [ofp_parser.OFPActionGroup(group_id)]

                    self.add_flow(dp, 32768, match_ip, actions)
                    self.add_flow(dp, 1, match_arp, actions)

                elif len(out_ports) == 1:
                    actions = [ofp_parser.OFPActionOutput(out_ports[0][0])]

                    self.add_flow(dp, 32768, match_ip, actions)
                    self.add_flow(dp, 1, match_arp, actions)
        print "Path installation finished in ", time.time() - computation_start 
        return paths_with_ports[0][src][1]

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        # print "Adding flow ", match, actions
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        print "switch_features_handler is called"
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        switch = ev.msg.datapath
        for p in ev.msg.body:
            self.bandwidths[switch.id][p.port_no] = p.curr_speed

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)

        # avoid broadcast from LLDP
        if eth.ethertype == 35020:
            return

        if pkt.get_protocol(ipv6.ipv6):  # Drop the IPV6 Packets.
            match = parser.OFPMatch(eth_type=eth.ethertype)
            actions = []
            self.add_flow(datapath, 1, match, actions)
            return None

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        if src not in self.hosts:
            self.hosts[src] = (dpid, in_port)

        out_port = ofproto.OFPP_FLOOD

        if arp_pkt:
            # print dpid, pkt
            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip
            if arp_pkt.opcode == arp.ARP_REPLY:
                self.arp_table[src_ip] = src
                h1 = self.hosts[src]
                h2 = self.hosts[dst]
                out_port = self.install_paths(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip)
                self.install_paths(h2[0], h2[1], h1[0], h1[1], dst_ip, src_ip) # reverse
            elif arp_pkt.opcode == arp.ARP_REQUEST:
                if dst_ip in self.arp_table:
                    self.arp_table[src_ip] = src
                    dst_mac = self.arp_table[dst_ip]
                    h1 = self.hosts[src]
                    h2 = self.hosts[dst_mac]
                    out_port = self.install_paths(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip)
                    self.install_paths(h2[0], h2[1], h1[0], h1[1], dst_ip, src_ip) # reverse

        # print pkt

        actions = [parser.OFPActionOutput(out_port)]

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        switch = ev.switch.dp
        ofp_parser = switch.ofproto_parser

        if switch.id not in self.switches:
            self.switches.append(switch.id)
            self.datapath_list[switch.id] = switch

            # Request port/link descriptions, useful for obtaining bandwidth
            req = ofp_parser.OFPPortDescStatsRequest(switch)
            switch.send_msg(req)

    @set_ev_cls(event.EventSwitchLeave, MAIN_DISPATCHER)
    def switch_leave_handler(self, ev):
        print ev
        switch = ev.switch.dp.id
        if switch in self.switches:
            self.switches.remove(switch)
            del self.datapath_list[switch]
            del self.adjacency[switch]

    @set_ev_cls(event.EventLinkAdd, MAIN_DISPATCHER)
    def link_add_handler(self, ev):
        s1 = ev.link.src
        s2 = ev.link.dst
        self.adjacency[s1.dpid][s2.dpid] = s1.port_no
        self.adjacency[s2.dpid][s1.dpid] = s2.port_no

    @set_ev_cls(event.EventLinkDelete, MAIN_DISPATCHER)
    def link_delete_handler(self, ev):
        s1 = ev.link.src
        s2 = ev.link.dst
        # Exception handling if switch already deleted
        try:
            del self.adjacency[s1.dpid][s2.dpid]
            del self.adjacency[s2.dpid][s1.dpid]
        except KeyError:
            pass

# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.

#

# Licensed under the Apache License, Version 2.0 (the "License");

# you may not use this file except in compliance with the License.

# You may obtain a copy of the License at

#

#    http://www.apache.org/licenses/LICENSE-2.0

#

# Unless required by applicable law or agreed to in writing, software

# distributed under the License is distributed on an "AS IS" BASIS,

# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or

# implied.

# See the License for the specific language governing permissions and

# limitations under the License.

 

# from ryu.base import app_manager

# from ryu.controller import mac_to_port

# from ryu.controller import ofp_event

# from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER

# from ryu.controller.handler import set_ev_cls

# from ryu.ofproto import ofproto_v1_3

# from ryu.ofproto import ofproto_v1_3_parser

# from ryu.lib.packet import packet

# from ryu.lib.packet import ethernet

# from ryu.lib.packet import ether_types

# from ryu.lib import mac

 

# from ryu.topology.api import get_switch, get_link

# from ryu.app.wsgi import ControllerBase

# from ryu.topology import event, switches

# import networkx as nx

 

# class ProjectController(app_manager.RyuApp):

#     OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

 

#     def __init__(self, *args, **kwargs):

#         super(ProjectController, self).__init__(*args, **kwargs)

#         self.mac_to_port = {}

#         self.topology_api_app = self

#         self.net=nx.DiGraph()

#         self.nodes = {}

#         self.links = {}

#         self.no_of_nodes = 0

#         self.no_of_links = 0

#         self.i=0

  

#     # Handy function that lists all attributes in the given object

#     def ls(self,obj):

#         print("\n".join([x for x in dir(obj) if x[0] != "_"]))

 

#     def add_flow(self, datapath, in_port, dst, actions):

#         ofproto = datapath.ofproto

#         parser = datapath.ofproto_parser      

#         match = datapath.ofproto_parser.OFPMatch( in_port=in_port, eth_dst=dst)

#         inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)] 

#         mod = datapath.ofproto_parser.OFPFlowMod(

#             datapath=datapath, match=match, cookie=0,

#             command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,

#             priority=1, instructions=inst)

#         datapath.send_msg(mod)

 

#     @set_ev_cls(ofp_event.EventOFPSwitchFeatures , CONFIG_DISPATCHER)

#     def switch_features_handler(self , ev):

#          print "switch_features_handler is called"

#          datapath = ev.msg.datapath

#          ofproto = datapath.ofproto

#             parser = datapath.ofproto_parser

#         match = parser.OFPMatch()

#             actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]

#         inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS , actions)]

#             mod = datapath.ofproto_parser.OFPFlowMod(

#             datapath=datapath, match=match, cookie=0,

#             command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,

#             priority=0, instructions=inst)

#         datapath.send_msg(mod)

  

#         ###add rule for multipath transmission in s1

#         if ev.msg.datapath.id == 1:

#           #in_port=1,src=10.0.0.1,dst=10.0.0.2,udp,udp_dst=5555--->group id 50

#           ofproto = datapath.ofproto

#           parser = datapath.ofproto_parser

    

#           #group 50--> port3:30%, port2:70%  

#           port_1 = 3

#           queue_1 = parser.OFPActionSetQueue(0)

#           actions_1 = [queue_1, parser.OFPActionOutput(port_1)]

 

#           port_2 = 2

#           queue_2 = parser.OFPActionSetQueue(0)

#           actions_2 = [queue_2, parser.OFPActionOutput(port_2)]

 

#           weight_1 = 30

#           weight_2 = 70

 

#           watch_port = ofproto_v1_3.OFPP_ANY

#           watch_group = ofproto_v1_3.OFPQ_ALL

 

#           buckets = [

#             parser.OFPBucket(weight_1, watch_port, watch_group, actions_1),

#             parser.OFPBucket(weight_2, watch_port, watch_group, actions_2)]

 

#           group_id = 50

#           req = parser.OFPGroupMod(

#             datapath, datapath.ofproto.OFPFC_ADD,

#             datapath.ofproto.OFPGT_SELECT, group_id, buckets)

#           datapath.send_msg(req)

 

#           match = parser.OFPMatch(in_port=1, eth_type=0x0800, ipv4_src="10.0.0.1", ipv4_dst="10.0.0.2", ip_proto=17, udp_dst=5555)

#           actions = [datapath.ofproto_parser.OFPActionGroup(50)]

#           inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,

#                                              actions)]

#               mod = datapath.ofproto_parser.OFPFlowMod(

#             datapath=datapath, match=match, cookie=0,

#             command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,

#             priority=3, instructions=inst)

#           datapath.send_msg(mod)

   

#         ###add rule for multipath transmission in s2     

#         if ev.msg.datapath.id == 2:

#           #in_port=1,src=10.0.0.1,dst=10.0.0.2--->output port:2

#           ofproto = datapath.ofproto

#           parser = datapath.ofproto_parser

#           match = parser.OFPMatch(in_port=1, eth_type=0x0800, ipv4_src="10.0.0.1", ipv4_dst="10.0.0.2", ip_proto=17, udp_dst=5555)

#           actions = [parser.OFPActionOutput(2)]

#           inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

#               mod = datapath.ofproto_parser.OFPFlowMod(

#             datapath=datapath, match=match, cookie=0,

#             command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,

#             priority=3, instructions=inst)

#           datapath.send_msg(mod)

       

#         ###add rule for multipath transmission in s3

#         if ev.msg.datapath.id == 3:

#           #in_port=1,src=10.0.0.1,dst=10.0.0.2--->output port:2

#           ofproto = datapath.ofproto

#           parser = datapath.ofproto_parser

#           match = parser.OFPMatch(in_port=1, eth_type=0x0800, ipv4_src="10.0.0.1", ipv4_dst="10.0.0.2", ip_proto=17, udp_dst=5555)

#           actions = [parser.OFPActionOutput(2)]

#           inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

#               mod = datapath.ofproto_parser.OFPFlowMod(

#             datapath=datapath, match=match, cookie=0,

#             command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,

#             priority=3, instructions=inst)

#           datapath.send_msg(mod)

       

#         ###add rule for multipath transmission in s4

#         if ev.msg.datapath.id == 4:

#           #in_port=1,src=10.0.0.1,dst=10.0.0.2--->output port:3

#           ofproto = datapath.ofproto

#           parser = datapath.ofproto_parser

#           match = parser.OFPMatch(in_port=1, eth_type=0x0800, ipv4_src="10.0.0.1", ipv4_dst="10.0.0.2", ip_proto=17, udp_dst=5555)

#           actions = [parser.OFPActionOutput(3)]

#           inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

#               mod = datapath.ofproto_parser.OFPFlowMod(

#             datapath=datapath, match=match, cookie=0,

#             command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,

#             priority=3, instructions=inst)

#           datapath.send_msg(mod)

         

#           #in_port=2,src=10.0.0.1,dst=10.0.0.2--->output port:3

#           ofproto = datapath.ofproto

#           parser = datapath.ofproto_parser

#           match = parser.OFPMatch(in_port=2, eth_type=0x0800, ipv4_src="10.0.0.1", ipv4_dst="10.0.0.2", ip_proto=17, udp_dst=5555)

#           actions = [parser.OFPActionOutput(3)]

#           inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

#               mod = datapath.ofproto_parser.OFPFlowMod(

#             datapath=datapath, match=match, cookie=0,

#             command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,

#             priority=3, instructions=inst)

#           datapath.send_msg(mod)  

  

#     @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)

#     def _packet_in_handler(self, ev):

#         msg = ev.msg

#         datapath = msg.datapath

#         ofproto = datapath.ofproto

#         parser = datapath.ofproto_parser

#         in_port = msg.match['in_port']

 

#         pkt = packet.Packet(msg.data)

#         eth = pkt.get_protocol(ethernet.ethernet)

 

#         dst = eth.dst

#         src = eth.src

#         dpid = datapath.id

#         self.mac_to_port.setdefault(dpid, {})

#         #print "nodes"

#         #print self.net.nodes()

#         #print "edges"

#         #print self.net.edges()

#         #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

       

#         if src not in self.net:

#             self.net.add_node(src)

#             self.net.add_edge(dpid,src,{'port':in_port})

#             self.net.add_edge(src,dpid)

#         if dst in self.net:

#             #print (src in self.net)

#             #print nx.shortest_path(self.net,1,4)

#             #print nx.shortest_path(self.net,4,1)

#             #print nx.shortest_path(self.net,src,4)

 

#             path=nx.shortest_path(self.net,src,dst)  

#             next=path[path.index(dpid)+1]

#             out_port=self.net[dpid][next]['port']

#         else:

#             out_port = ofproto.OFPP_FLOOD

 

#         actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

#         # install a flow to avoid packet_in next time

#         if out_port != ofproto.OFPP_FLOOD:

#             self.add_flow(datapath, in_port, dst, actions)

 

#         out = datapath.ofproto_parser.OFPPacketOut(

#             datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,

#             actions=actions)

#         datapath.send_msg(out)

   

#     @set_ev_cls(event.EventSwitchEnter)

#     def get_topology_data(self, ev):

#         switch_list = get_switch(self.topology_api_app, None)  

#         switches=[switch.dp.id for switch in switch_list]

#         self.net.add_nodes_from(switches)

        

#         print "**********List of switches"

#         for switch in switch_list:

#           #self.ls(switch)

#           print switch

#           #self.nodes[self.no_of_nodes] = switch

#           #self.no_of_nodes += 1

       

#         links_list = get_link(self.topology_api_app, None)

#         #print links_list

#         links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]

#         #print links

#         self.net.add_edges_from(links)

#         links=[(link.dst.dpid,link.src.dpid,{'port':link.dst.port_no}) for link in links_list]

#         #print links

#         self.net.add_edges_from(links)

#         print "**********List of links"

#         print self.net.edges()