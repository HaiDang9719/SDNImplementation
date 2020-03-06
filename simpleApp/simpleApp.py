from ryu.base import app_manager
from ryu.lib import stplib
from ryu.ofproto import ofproto_v1_3
from ryu.controller.handler import set_ev_cls
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.lib import dpid as dpid_lib
from ryu.lib.packet import packet, ethernet, ether_types

class simpleApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
   

    def __init__(self, *args, **kwargs):
        super(simpleApp, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
    def hex_array(self, data):
        """
        Convert six.binary_type or bytearray into array of hexes to be printed.
        """
        # convert data into bytearray explicitly
        return ' '.join('0x%02x' % byte for byte in bytearray(data))
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
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

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if msg.reason == ofproto.OFPR_NO_MATCH:
            reason = "NO MATCH"
        elif msg.reason == ofproto.OFPR_ACTION:
            reason = "APPLY ACTION"
        elif msg.reason == ofproto. OFPR_INVALID_TTL:
            reason = "INVALID TTL"
        else:
            reason = "UNKOWN"

        self.logger.info("OFPPacketIn Received: " 
        "buffer_id = %x total_len = %d reason = %s "
        "table_id = %d cookie = %d match = %s",
        msg.buffer_id, msg.total_len, reason, msg.table_id, msg.cookie, msg.match)
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            #ignore lldp packet(Link Layer Discovery Protocol, a vendor-neutral link 
            # layer protocol used by network devices for advertising their identity, capabilities,
            # and neighbors on a local area network based on IEEE 802 technology, pricipally wired Ethernet - Wikipedia)
            return
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in dpid: %s Source: %s Destination: %s In port:%s",
         dpid, src, dst, in_port)

        #learn a mac address to avoid FLOOD next time
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

         # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto

        if msg.reason == ofp.OFPPR_ADD:
            reason = "ADD"
        elif msg.reason == ofp.OFPPR_DELETE:
            reason = "DELETE"
        elif msg.reason == ofp.OFPPR_MODIFY:
            reason = "MODIFY"
        else:
            reason = "UNKNOWN"
        self.logger.info('OFPPortStatus received: reason = %s desc = %s', reason, msg.desc)