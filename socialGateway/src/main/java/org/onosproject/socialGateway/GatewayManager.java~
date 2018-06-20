/*
 * Copyright 2017-present Open Networking Laboratory
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.onosproject.socialGateway;

import com.google.common.collect.Maps;
import org.apache.felix.scr.annotations.*;
import org.onlab.packet.*;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.device.DeviceEvent;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.device.DeviceListener;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.nio.ByteBuffer;
import java.util.Map;
import java.util.Random;
import java.util.Optional;
import org.onosproject.dhcp.DhcpService;
//import org.onosproject.xmpp_application.xmpp_service;


/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true,enabled=true)
@Service
public class gatewayManager implements gatewayService{


    // Instantiates the relevant services.
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected DhcpService dhcpService;

//    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
//    protected xmpp_service XmppService;

//    @Reference(cardinality=ReferenceCardinality.MANDATORY_UNARY)
//    protected ovswitch_service ovservice;


    /*
     * Defining macTables as a concurrent map allows multiple threads and packets to
     * use the map without an issue.
     */
    protected Map<DeviceId, Map<Ip4Address, PortNumber>> routingTable = Maps.newConcurrentMap();
    private Map<Ip4Address, Ip4Address> local_remote = Maps.newConcurrentMap(); //for mapping arp replies
    private Map<Ip4Address, Ip4Address> src_dst = Maps.newConcurrentMap(); //matches on dst address
    private Map<Ip4Address, Ip4Address> dst_src = Maps.newConcurrentMap(); //matches on src address
    private Map<Ip4Address,PortNumber> access_map = Maps.newConcurrentMap(); //contains access rules
    private Map<Ip4Address, MacAndPort> ip4_to_MacAndPort = Maps.newConcurrentMap();
    /**
     * Below to maps, map learnt interface names, with mac, port.
     */
    private Map<String, MacAndPort> face_to_MacAndPort = Maps.newConcurrentMap();
    private ApplicationId appId;
    private PacketProcessor processor;
    private DeviceListener deviceListener = new InnerDeviceListener();
    private boolean switch_ip_known = false;
    private MacAddress switch_mac; //my mac address
    private Ip4Address switch_ip; //normally switch will not have IP but need this to create dummy ARP requests.
    private final Logger log = LoggerFactory.getLogger(getClass());
    @Activate
    protected void activate() {
        log.info("socialGateway Started");
        appId = coreService.getAppId("org.onosproject.socialGateway"); //equal to the name shown in pom.xml file
        deviceService.addListener(deviceListener);
        processor = new routerPacketProcessor();
        packetService.addProcessor(processor, PacketProcessor.director(3));

        /*
         * Restricts packet types to IPV4 and ARP by only requesting those types.
         */
        packetService.requestPackets(DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4).build(), PacketPriority.REACTIVE, appId, Optional.empty());
        packetService.requestPackets(DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_ARP).build(), PacketPriority.REACTIVE, appId, Optional.empty());

        //populate_arped_candidates(Ip4Address.valueOf("192.168.1.101"));
        //translate_address("192.168.1.101","10.10.10.100",false);
        //translate_address("10.10.10.100","192.168.1.101",true);
        //populate_arped_candidates(Ip4Address.valueOf("10.0.1.1"));
        //populate_arped_candidates(Ip4Address.valueOf("10.0.2.1"));
        //populate_arped_candidates(Ip4Address.valueOf("10.0.3.1"));
        //Iterable<Ip4Address> list = dhcpService.getAvailableIPs();
        //log.info(" "+dhcpService.getLeaseTime());
        //log.info("");
    }

    @Deactivate
    protected void deactivate() {
        deviceService.removeListener(deviceListener);
        log.info("socialGateway Stopped");
    }

    private class routerPacketProcessor implements PacketProcessor
    {
        @Override
        public void process(PacketContext pc) {
            //log.info(pc.toString());
            //log.info(pc.inPacket().receivedFrom().toString());
            ConnectPoint cp = pc.inPacket().receivedFrom();
            PortNumber incoming_port = cp.port();
            switch_mac = MacAddress.valueOf(getMacAddress(cp));
            if (!switch_ip_known){
                switch_ip = dhcpService.getIPAddress(switch_mac);
                if (switch_ip==null)
                    log.error("Switch could not get IP address assignment.");
                else {
                    switch_ip_known=true;
                    log.info("IP address assigned to switch is " + switch_ip.toString());
                }
            }
            MacAddress senderMac = pc.inPacket().parsed().getSourceMAC();
            //log.info("switch_mac "+switch_mac);
            /**
             * Use this opportunity to refresh Port,Mac information.
             */
//            for (Ip4Address ip:ip4_to_MacAndPort.keySet()){
//                if (ip4_to_MacAndPort.get(ip).ARP==true && ip4_to_MacAndPort.get(ip).MAC!=null)
//                    sendArpRequest(cp,ip.toString());
//            }
            System.out.println(pc.inPacket().parsed().getEtherType());
            System.out.println(Ethernet.TYPE_ARP);
            if (pc.inPacket().parsed().getEtherType()==Ethernet.TYPE_ARP)
            {
                ARP arp = (ARP)pc.inPacket().parsed().getPayload();
                short vlanID = pc.inPacket().parsed().getVlanID();
                byte[] b = arp.getTargetProtocolAddress();
                byte[] b2 = arp.getSenderProtocolAddress();
                Ip4Address ipaddress = Ip4Address.valueOf(b);
                Ip4Address sendersIP = Ip4Address.valueOf(b2);
                senderMac = MacAddress.valueOf(arp.getSenderHardwareAddress());
                ip4_to_MacAndPort.put(sendersIP, new MacAndPort(senderMac,incoming_port,true));
                //log.info(pc.inPacket().parsed().getDestinationMACAddress().toString());
                if (local_remote.containsKey(ipaddress) || ipaddress.equals(switch_ip)) {
                    TrafficTreatment treatment = DefaultTrafficTreatment.builder().setOutput(cp.port()).build();
                    Ethernet eth = createArpResponse(pc,ipaddress);
                    OutboundPacket packet = new DefaultOutboundPacket(cp.deviceId(),
                            treatment, ByteBuffer.wrap(eth.serialize()));
                    packetService.emit(packet);
                    //log.info("sent out reply");
                }

            }
            else if (pc.inPacket().parsed().getEtherType()==Ethernet.TYPE_IPV4)
            {
                /*
                * check to see ip address matches
                * */
                IPv4 ipv4 = (IPv4) pc.inPacket().parsed().getPayload();
                Ip4Address src_add = Ip4Address.valueOf(ipv4.getSourceAddress());
                Ip4Address dst_add = Ip4Address.valueOf(ipv4.getDestinationAddress());
                log.info("LEARNT/UPDATED MAC "+senderMac.toString()+", PORT "+incoming_port+" FOR "+src_add.toString());
                ip4_to_MacAndPort.put(src_add, new MacAndPort(senderMac,incoming_port,true));
                //log.info(src_add.toString());
                //log.info(IpAddress.valueOf(ipv4.getSourceAddress()).toString());
                //log.info(IpAddress.valueOf(ipv4.getDestinationAddress()).toString());
               // log.info(dst_add.toString());
                /*
                if this node did not initiate dns request it does
                * not knows the ip4 address of the device that will connect to
                * it.
                * */
                PortNumber pn = access_map.get(dst_add);
                /*if (pn != null)
                    log.info("port number is "+pn.toLong());
                else
                    log.info("no port number found for address "+dst_add.toString());
                log.info("incoming port number is "+incoming_port.toLong());
                log.info("COMPARE PORT's ");*/
                /**
                 * The below kind of acts as access control, allow packets from a incoming port
                 * to a L3 destination only if this access has been allowed.
                 */
                if (pn != null && pn.exactlyEquals(incoming_port)){
                    if (!src_dst.containsKey(src_add))
                    {
                        Ip4Address mapped_src = null;
                        if (src_dst.get(src_add) == null) {
                            mapped_src = find_free_address();
                            ip4_to_MacAndPort.put(mapped_src,new MacAndPort(senderMac,incoming_port,false));
                        } else
                            mapped_src = src_dst.get(src_add);
                        src_dst.putIfAbsent(src_add,mapped_src);
                        dst_src.putIfAbsent(mapped_src,src_add);
                        populate_arped_candidates(mapped_src);
                    }
                }

                MacAddress dst_mac = ip4_to_MacAndPort.containsKey(dst_add)?ip4_to_MacAndPort.get(dst_add).MAC:null;
                if (dst_mac == null) {
                    // Try DHCP service before sending a ARP request out.
                     dst_mac = dhcpService.getMacAddress(dst_add);
                     if (dst_mac == null)
                     {
                         log.error("MAC learnt for " + dst_add.toString() + " is NULL!!");
                         sendArpRequest(cp,dst_add.toString());
                     }
                }
                PortNumber dst_port = ip4_to_MacAndPort.containsKey(dst_add)?ip4_to_MacAndPort.get(dst_add).PORT:null;
                if (dst_port == null)
                    dst_port = dhcpService.getPortNumber(dst_add);
                    if (dst_port == null)
                        log.error("PORT learnt for "+dst_add.toString()+" is NULL");

                if (dst_mac != null && dst_port!= null && dst_src.containsKey(dst_add)) {
                    TrafficSelector selector = DefaultTrafficSelector.builder()
                            .matchEthType(Ethernet.TYPE_IPV4)
                            //.matchEthSrc(MacAddress.valueOf("00:00:00:00:00:01"))
                            .matchIPDst(IpPrefix.valueOf(dst_add.toString()+"/32"))
                            .build();
                    TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                            //.setEthDst(MacAddress.valueOf("00:00:00:00:00:00"))
                            .setEthDst(dst_mac)
                            .setIpDst(IpAddress.valueOf(dst_src.get(dst_add).toString()))
                            //.setOutput(PortNumber.portNumber(1))
                            .setOutput(dst_port)
                            .build();
                    FlowRule fr = DefaultFlowRule.builder()
                            .withSelector(selector)
                            .withTreatment(treatment)
                            //.forDevice(cp.deviceId()).withPriority(PacketPriority.REACTIVE.priorityValue())
                            .forDevice(cp.deviceId()).withPriority(45000)
                            .makePermanent()
                            //.makeTemporary(60)
                            .fromApp(appId).build();
                    flowRuleService.applyFlowRules(fr);
                    log.info("installed flow rule dst to src");
                }
                else if (dst_mac != null && dst_port != null && src_dst.containsKey(src_add)) {
                    TrafficSelector selector = DefaultTrafficSelector.builder()
                            .matchEthType(Ethernet.TYPE_IPV4)
                            //.matchEthSrc(MacAddress.valueOf("00:00:00:00:00:01"))
                            .matchIPSrc(IpPrefix.valueOf(src_add.toString()+"/32"))
                            .build();
                    TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                            //.setEthDst(MacAddress.valueOf("FF:FF:FF:FF:FF:FF"))
                            .setEthDst(dst_mac)
                            .setIpSrc(IpAddress.valueOf(src_dst.get(src_add).toString()))
                            //.setOutput(PortNumber.portNumber(9))
                            .setOutput(dst_port)
                            .build();
                    FlowRule fr = DefaultFlowRule.builder()
                            .withSelector(selector)
                            .withTreatment(treatment)
                            //.forDevice(cp.deviceId()).withPriority(PacketPriority.REACTIVE.priorityValue())
                            .forDevice(cp.deviceId()).withPriority(45000)
                            .makePermanent()
                            //.makeTemporary(60)
                            .fromApp(appId).build();
                    flowRuleService.applyFlowRules(fr);
                    log.info("installed flow rule src to dst");
                }

            }

        }
    }

    private class MacAndPort
    {
        public MacAddress MAC;
        public PortNumber PORT;
        public Boolean ARP;
        public MacAndPort(MacAddress mac,PortNumber port, Boolean arp) {
            MAC = mac; PORT = port; ARP = arp;
        }
    }

    public void test_dhcp()
    {
        Iterable<Ip4Address> list = dhcpService.getAvailableIPs();
        for (Ip4Address ip:list)
            log.info(ip.toString());
    }

    private MacAddress gen_fake_mac()
    {
        char[] literals = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
        char[] mac = new char[17];
        for (int i=0;i<mac.length;i++)
        {
            if ((i+1)%3==0)
                mac[i]=':';
            else{
                Random random = new Random();
                int num = random.nextInt(literals.length);
                mac[i] = literals[num];
            }
        }
        String mac_addr = new String(mac);
        return MacAddress.valueOf(mac_addr);
    }

    public Ip4Address find_free_address(){

        MacAddress mac = gen_fake_mac();
        Ip4Address ip4Address = dhcpService.getIPAddress(mac);
        return ip4Address;
    }
    private class InnerDeviceListener implements DeviceListener
    {
        @Override
        public void event(DeviceEvent event)
        {
            String portName = null;
            String portMac = null;
            PortNumber portNum = null;
            switch(event.type())
            {
                case DEVICE_ADDED:
                    event.subject();
                    break;
                case PORT_ADDED:
                    event.subject();
                    portName = event.port().annotations().value("portName");
                    portMac = event.port().annotations().value("portMac");
                    portNum = event.port().number();
                    log.info(event.subject().toString());
                    log.info(portMac);
                    log.info(portName);
                    face_to_MacAndPort.put(portName,new MacAndPort(MacAddress.valueOf(portMac),portNum,false));
                    break;
                case PORT_REMOVED:
                    event.subject();
                    portName = event.port().annotations().value("portName");
                    portMac = event.port().annotations().value("portMac");
                    portNum = event.port().number();
                    log.info(event.subject().toString());
                    log.info(portMac);
                    log.info(portName);
                    face_to_MacAndPort.remove(portName);
                    break;
                case PORT_UPDATED:
                    event.subject();
                    portName = event.port().annotations().value("portName");
                    portMac = event.port().annotations().value("portMac");
                    portNum = event.port().number();
                    log.info(event.subject().toString());
                    log.info(portMac);
                    log.info(portName);
                    face_to_MacAndPort.put(portName,new MacAndPort(MacAddress.valueOf(portMac),portNum,false));
                    break;
                default:
                    break;
            }
        }
    }

    private String getMacAddress(ConnectPoint cp)
    {
        String deviceID = cp.deviceId().toString();
        deviceID = deviceID.substring(deviceID.length()-12);
        char[] dID = deviceID.toCharArray();
        char[] mac = new char[dID.length+5];
        for (int i=0,j=0;i<mac.length;i++)
        {
            if (i!=0 && (i+1)%3==0)
                mac[i]=':';
            else
                mac[i]=dID[j++];
        }
        //log.info(did.substring(did.length()-12));
        //log.info(MacAddress.valueOf(did.substring(did.length()-12)).toString());
        String s_mac = new String(mac);
        //log.info(s_mac);
        return s_mac;
    }
    private Ethernet createArpResponse(PacketContext pc, Ip4Address ipaddress) {
        Ethernet request = pc.inPacket().parsed();
        //Ip4Address srcIP = Ip4Address.valueOf("10.0.1.1");
        //MacAddress srcMac = MacAddress.valueOf("A9:DC:3C:F1:6A:0B");
        Ethernet arpReply = ARP.buildArpReply(ipaddress, switch_mac, request);
        return arpReply;

    }

    private Ethernet sendArpRequest(ConnectPoint cp, String ip_address)
    {
        byte[] senderMacAddress = switch_mac.toBytes();
        byte[] senderIpAddress = switch_ip.toOctets();
        byte[] targetAddress = Ip4Address.valueOf(ip_address).toOctets();
        Ethernet arpRequest = ARP.buildArpRequest(senderMacAddress,senderIpAddress,targetAddress,(short)-1);
        TrafficTreatment treatment = DefaultTrafficTreatment.builder().setOutput(cp.port()).build();
        OutboundPacket packet = new DefaultOutboundPacket(cp.deviceId(),
                treatment, ByteBuffer.wrap(arpRequest.serialize()));
        if (packet != null) {
            packetService.emit(packet);
            //log.info("sent out ARP request for "+ ip_address);
        }
        return arpRequest;
    }

    private void populate_arped_candidates(Ip4Address ipaddress)
    {
        local_remote.putIfAbsent(ipaddress,ipaddress);
    }

    public void populate_arped_addresseses(String address, String face_name){
        MacAddress mac = face_to_MacAndPort.containsKey(face_name)?face_to_MacAndPort.get(face_name).MAC:null;
        PortNumber port = face_to_MacAndPort.containsKey(face_name)?face_to_MacAndPort.get(face_name).PORT:null;
        if (mac==null){
            log.error("No MAC mapping for address "+address);
            return;
        }
        if (port==null){
            log.error("No PORT mapping for address "+address);
            return;
        }
        ip4_to_MacAndPort.put(Ip4Address.valueOf(address), new MacAndPort(mac, port, false));
        populate_arped_candidates(Ip4Address.valueOf(address));
    }


    /**
     * Want controller to start sending our ARP request for these addresses.
     * @param address
     */
    public void initiate_arp_requests(String address){
        ip4_to_MacAndPort.putIfAbsent(Ip4Address.valueOf(address),new MacAndPort(null,null,true));
    }

    public void translate_address(String match_address, String new_address, Boolean incoming){
        if (incoming==false)
            dst_src.putIfAbsent(Ip4Address.valueOf(match_address), Ip4Address.valueOf(new_address));
        else
            src_dst.putIfAbsent(Ip4Address.valueOf(match_address), Ip4Address.valueOf(new_address));

    }

    /* port binds to tunnel, one for each user
    * address binds to device, allow access to device
    * for incoming traffic from this port.*/
    public void allow_access(String admin, String address)
    {
        PortNumber port = face_to_MacAndPort.containsKey(admin)?face_to_MacAndPort.get(admin).PORT:null;
        if (port == null){
            log.error("No port found corresponding to face "+admin);
            return;
        }
        access_map.putIfAbsent(Ip4Address.valueOf(address),port);
    }

    public void remove_arped_candidates(String address){
        // will have to handle removal
    }


    public void do_something()
    {
        //log.info("Doing something ha ha ha");
    }


}
