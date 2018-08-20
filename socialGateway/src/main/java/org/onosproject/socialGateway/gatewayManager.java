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
import javafx.util.Pair;
import org.apache.felix.scr.annotations.*;
import org.onlab.packet.*;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.*;
import org.onosproject.net.device.DeviceEvent;
import org.onosproject.net.flow.*;
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
import java.util.*;

import org.onosproject.dhcp.DhcpService;

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



    /*
     * Defining macTables as a concurrent map allows multiple threads and packets to
     * use the map without an issue.
     */
    protected Map<DeviceId, Map<Ip4Address, PortNumber>> routingTable = Maps.newConcurrentMap();
    private Map<Ip4Address, Ip4Address> local_remote = Maps.newConcurrentMap(); //for mapping arp replies
    private Map<Ip4Address, Ip4Address> rem_mapped = Maps.newConcurrentMap(); //matches on dst address
    private Map<Ip4Address, Ip4Address> mapped_rem = Maps.newConcurrentMap(); //matches on src address
    private Map<endpoint, endpoint> x_rem_mapped = Maps.newConcurrentMap(); //matches on dst endpoint
    private Map<endpoint, endpoint> x_mapped_rem = Maps.newConcurrentMap(); //matches on src address
    private Map<String, GatewaySwitch> gatewaySwitchMap = Maps.newConcurrentMap();
    /**
     * Below to maps, map learnt interface names, with mac, port.
     */
    private ApplicationId appId;
    private PacketProcessor processor;
    private DeviceListener deviceListener = new InnerDeviceListener();
    private final Logger log = LoggerFactory.getLogger(getClass());
    private DeviceId masterSwitchId = null;
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
        getDevices();
        masterSwitchId = getMasterSwitch();

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
            DeviceId gatewaySwitchId = cp.deviceId();
            GatewaySwitch gatewaySwitch = gatewaySwitchMap.get(gatewaySwitchId.toString());
            PortNumber incoming_port = cp.port();
            MacAddress switch_mac = MacAddress.valueOf(getMacAddress(cp));
            if (gatewaySwitch.ipAddress==null){
                gatewaySwitch.ipAddress = dhcpService.getIPAddress(switch_mac);
                if (gatewaySwitch.ipAddress==null)
                    log.error(String.format("switch %s could not be assigned IP address.",gatewaySwitchId));
                else {
                    log.info(String.format("IP address assigned to switch %s " +
                            "is %s",gatewaySwitchId,gatewaySwitch.ipAddress.toString()));
                }
            }
            MacAddress senderMac = pc.inPacket().parsed().getSourceMAC();

            /* If this switch is not master switch, drop all traffic on all ports, essentially disabling
             * the switch */
            if (!gatewaySwitchId.equals(masterSwitchId)){
                TrafficSelector selector = DefaultTrafficSelector.builder()
                        .matchInPort(incoming_port)
                        .build();
                TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                        .drop()
                        .build();
                FlowRule fr = DefaultFlowRule.builder()
                        .withSelector(selector)
                        .withTreatment(treatment)
                        .forDevice(gatewaySwitchId).withPriority(45000)
                        .makePermanent()
                        .fromApp(appId).build();
                flowRuleService.applyFlowRules(fr);
                log.info(String.format("Installed rule to drop all traffic on port %s on switch %s master is %s",
                        incoming_port.toString(), gatewaySwitchId.toString(), masterSwitchId));
                return;
            }

            if (pc.inPacket().parsed().getEtherType()==Ethernet.TYPE_ARP)
            {
                ARP arp = (ARP)pc.inPacket().parsed().getPayload();
                short vlanID = pc.inPacket().parsed().getVlanID();
                byte[] b = arp.getTargetProtocolAddress();
                byte[] b2 = arp.getSenderProtocolAddress();
                Ip4Address ipaddress = Ip4Address.valueOf(b);
                Ip4Address sendersIP = Ip4Address.valueOf(b2);
                senderMac = MacAddress.valueOf(arp.getSenderHardwareAddress());
                if (!gatewaySwitch.ip4_to_MacAndPort.containsKey(sendersIP))
                    gatewaySwitch.ip4_to_MacAndPort.put(sendersIP, new HashSet<MacAndPort>());
                gatewaySwitch.ip4_to_MacAndPort.get(sendersIP).add(new MacAndPort(senderMac,incoming_port,true));
                //log.info(pc.inPacket().parsed().getDestinationMACAddress().toString());
                /*Here I have to make sure that ARP responses point to the master switch
                * ARP request will be likely received via all switched but let only the
                * master switch reply.*/
                if (local_remote.containsKey(ipaddress) || ipaddress.equals(gatewaySwitch.ipAddress)) {
                    TrafficTreatment treatment = DefaultTrafficTreatment.builder().setOutput(cp.port()).build();
                    Ethernet eth = createArpResponse(cp, pc, ipaddress);
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
                endpoint source_endpoint = new endpoint(src_add.toString(), gatewaySwitch.portToPeer.get(incoming_port));
//                log.info(String.format("LEARNT/UPDATED MAC %s, PORT %s FOR %s on SWITCH %s",
//                        senderMac.toString(),incoming_port.toString(), src_add.toString(), gatewaySwitchId.toString() ));
                // switches do not change MAC addresses only routers do.
                if (!gatewaySwitch.ip4_to_MacAndPort.containsKey(src_add))
                    gatewaySwitch.ip4_to_MacAndPort.put(src_add, new HashSet<MacAndPort>());
                gatewaySwitch.ip4_to_MacAndPort.get(src_add).add(new MacAndPort(senderMac,incoming_port,true));
                //log.info(src_add.toString());
                //log.info(IpAddress.valueOf(ipv4.getSourceAddress()).toString());
                //log.info(IpAddress.valueOf(ipv4.getDestinationAddress()).toString());
               // log.info(dst_add.toString());
                /*
                if this node did not initiate dns request it does
                * not knows the ip4 address of the device that will connect to
                * it.
                * */
                /* This list contains ports aka tunnels which have access to the destination address*/
                List<PortNumber> accessList = gatewaySwitch.access_map.
                        containsKey(dst_add)?gatewaySwitch.access_map.get(dst_add):null;
                boolean access_allowed = false;
                if (accessList != null) {
                    for (PortNumber pn : accessList) {
                        if (pn.exactlyEquals(incoming_port)) {
                            access_allowed = true;
                            break;
                        }

                    }
                }
                /*if (pn != null)
                    log.info("port number is "+pn.toLong());
                else
                    log.info("no port number found for address "+dst_add.toString());
                log.info("incoming port number is "+incoming_port.toLong());
                log.info("COMPARE PORT's ");*/
                /**
                 * The below kind of acts as access control, allow packets from a incoming port
                 * to a L3 destination only if this access has been allowed.
                 * TODO devices src addresses for incoming traffic can clash, device in multiple domains have same address
                 * TODO should I use src_add, port tuple for this purpose.
                 */
                if (access_allowed){
                    Ip4Address mapped_src = null;
                    if (x_rem_mapped.get(source_endpoint) == null) {
                        mapped_src = find_free_address();
                        log.info(String.format("Mapped %s to %s",src_add, mapped_src));
                        //TODO- clash will happen below.
                    } else
                        mapped_src = x_rem_mapped.get(source_endpoint).ipaddress;
                    endpoint mapped_endpoint = new endpoint(mapped_src.toString(),"PLO");
                    x_rem_mapped.putIfAbsent(source_endpoint,mapped_endpoint);
                    x_mapped_rem.putIfAbsent(mapped_endpoint,source_endpoint);
                    if (!gatewaySwitch.ip4_to_MacAndPort.containsKey(mapped_src))
                        gatewaySwitch.ip4_to_MacAndPort.put(mapped_src, new HashSet<MacAndPort>());
                    gatewaySwitch.ip4_to_MacAndPort.get(mapped_src).add(new MacAndPort(senderMac,incoming_port,false));
                    populate_arped_candidates(mapped_src);
                }
                MacAddress dst_mac = null;
                PortNumber dst_port = null;
                Set<MacAndPort> MacAndPorts = gatewaySwitch.ip4_to_MacAndPort.containsKey(dst_add)
                        ?gatewaySwitch.ip4_to_MacAndPort.get(dst_add)
                        :null;
                if (MacAndPorts == null || MacAndPorts.size() == 0){
                    dst_mac =  dhcpService.getMacAddress(dst_add);
                    dst_port = dhcpService.getPortOnSwitch(dst_mac,gatewaySwitchId);
                    MacAndPorts = new HashSet<>();
                    MacAndPorts.add(new MacAndPort(dst_mac,dst_port,false));
                } else{
                    Iterator<MacAndPort> itr= MacAndPorts.iterator();
                    if (itr.hasNext()) {
                        MacAndPort MP = itr.next();
                        dst_mac = MP.MAC; //Dst MAC of device will be same.
                        dst_port = MP.PORT;
                    }
                }

                if (dst_mac == null)
                {
//                         log.error("MAC learnt for " + dst_add.toString() + " is NULL!!");
                    sendArpRequest(cp,dst_add.toString());
                    return;
                }
                if (dst_port == null) {
                    if (dst_port == null) {
//                            log.error("PORT learnt for "+dst_add.toString()+" is NULL");
                        sendArpRequest(cp, dst_add.toString());
                        return;
                    }
                }
                /**
                 * dst_endpoint specified the context of the dst ip address in the packet.
                 * it could be
                 * If the packet is flowing from PLO to CLO the dst address is the mapped
                 * address in the PLO domain, which needs to be translated to remote address
                 * **/
                endpoint dst_endpoint = new endpoint(dst_add.toString(), gatewaySwitch.portToPeer.get(incoming_port));
                if (x_mapped_rem.containsKey(dst_endpoint)) {
                    TrafficSelector selector = DefaultTrafficSelector.builder()
                            .matchEthType(Ethernet.TYPE_IPV4)
                            .matchIPDst(IpPrefix.valueOf(dst_add.toString()+"/32"))
                            .build();
                    TrafficTreatment.Builder trafficBuilder = DefaultTrafficTreatment.builder()
                            .setEthDst(dst_mac)
                            .setIpDst(x_mapped_rem.get(dst_endpoint).ipaddress);
                    for (MacAndPort macAndPort:MacAndPorts){
                            trafficBuilder.setOutput(macAndPort.PORT);
                    }
                    TrafficTreatment treatment = trafficBuilder.build();

                    FlowRule fr = DefaultFlowRule.builder()
                            .withSelector(selector)
                            .withTreatment(treatment)
                            //.forDevice(cp.deviceId()).withPriority(PacketPriority.REACTIVE.priorityValue())
                            .forDevice(cp.deviceId()).withPriority(45000)
                            .makePermanent()
                            //.makeTemporary(60)
                            .fromApp(appId).build();
                    flowRuleService.applyFlowRules(fr);
                    log.info(String.format("Installed flow rule for MAPPED %s to REMOTE %s on %s" +
                                    "ETH_DST %s OUT_PORT %s",
                            dst_add.toString(),x_mapped_rem.get(dst_endpoint).ipaddress.toString(), gatewaySwitchId.toString(),
                            dst_mac.toString(), dst_port.toString()));
                }
                else if (x_rem_mapped.containsKey(source_endpoint)) {
                    TrafficSelector selector = DefaultTrafficSelector.builder()
                            .matchEthType(Ethernet.TYPE_IPV4)
                            //.matchEthSrc(MacAddress.valueOf("00:00:00:00:00:01"))
                            .matchIPSrc(IpPrefix.valueOf(src_add.toString()+"/32"))
                            .build();
                    TrafficTreatment.Builder trafficBuilder = DefaultTrafficTreatment.builder()
                            .setEthDst(dst_mac)
                            .setIpSrc(x_rem_mapped.get(source_endpoint).ipaddress);
                    for (MacAndPort macAndPort:MacAndPorts){
                        trafficBuilder.setOutput(macAndPort.PORT);
                    }
                    TrafficTreatment treatment = trafficBuilder.build();
                    FlowRule fr = DefaultFlowRule.builder()
                            .withSelector(selector)
                            .withTreatment(treatment)
                            //.forDevice(cp.deviceId()).withPriority(PacketPriority.REACTIVE.priorityValue())
                            .forDevice(cp.deviceId()).withPriority(45000)
                            .makePermanent()
                            //.makeTemporary(60)
                            .fromApp(appId).build();
                    flowRuleService.applyFlowRules(fr);
                    log.info(String.format("Installed flow rule for REMOTE %s to MAPPED %s on %s" +
                                    "ETH_DST %s OUT_PORT %s",
                            src_add,x_rem_mapped.get(source_endpoint).ipaddress.toString(), gatewaySwitchId.toString(),
                            dst_mac.toString(), dst_port.toString()));
                }
                /* Prevent Broadcast traffic */
                if (gatewaySwitch.clo_port.containsKey(incoming_port)) {
                    TrafficSelector selector = DefaultTrafficSelector.builder()
                            .matchEthType(Ethernet.TYPE_IPV4)
                            .matchIPSrc(IpPrefix.valueOf("255.255.255.255" + "/32"))
                            .matchInPort(incoming_port)
                            .build();

                    TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                            //.setEthDst(MacAddress.valueOf("FF:FF:FF:FF:FF:FF"))
                            .drop()
                            .build();
                    FlowRule fr = DefaultFlowRule.builder()
                            .withSelector(selector)
                            .withTreatment(treatment)
                            .forDevice(cp.deviceId()).withPriority(45000)
                            .makePermanent()
                            .fromApp(appId).build();
                    flowRuleService.applyFlowRules(fr);
                    log.info(String.format("Flow rule to prevent broadcast traffic from PORT %s on switch %s",
                            incoming_port.toString(), gatewaySwitchId.toString()));
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

        @Override
        public boolean equals(Object o){
            if (o == this)
                return true;
            else if (!(o instanceof MacAndPort))
                return false;
            else if (((MacAndPort) o).MAC.equals(this.MAC) && ((MacAndPort) o).PORT.equals(this.PORT))
                return true;
            else
                return false;
        }

        @Override
        public int hashCode(){
            int hc_mac = this.MAC==null?0:this.MAC.hashCode();
            int hc_port = this.PORT==null?0:this.PORT.hashCode();
            return hc_mac*19+hc_port*13;
        }
    }
    /* This class combines the remote address with peer name. */
    private class endpoint{
        public Ip4Address ipaddress;
        public String  peer_name;
        public endpoint(String address, String peer){
            ipaddress = Ip4Address.valueOf(address);
            peer_name = peer;
        }
        @Override
        public boolean equals(Object o){
            if (o==this)
                return true;
            else if (!(o instanceof endpoint))
                return false;
            else {
                endpoint other = (endpoint) o;
                if (this.ipaddress.equals(other.ipaddress) && this.peer_name.equals(other.peer_name))
                    return true;
                else
                    return false;
            }
        }

        @Override
        public int hashCode(){
            int t_ip = this.ipaddress==null?0:this.ipaddress.hashCode();
            int t_peer = this.peer_name==null?0:this.peer_name.hashCode();
            return t_ip*19+t_peer*13;
        }
    }

    private class GatewaySwitch
    {
        public GatewaySwitch(String id){
            switchID = id;
            ipAddress = null;
        }
        String switchID;
        Ip4Address ipAddress;
        public Map<Ip4Address, Set<MacAndPort>> ip4_to_MacAndPort = Maps.newConcurrentMap();
        public Map<String, MacAndPort> face_to_MacAndPort = Maps.newConcurrentMap();
        private Map<Ip4Address,List<PortNumber>> access_map = Maps.newConcurrentMap(); //contains access rules
        public Map<PortNumber,Boolean> clo_port = Maps.newConcurrentMap(); //if true this port feeds into a clo tunnel.
        public Map<PortNumber, String> portToPeer = Maps.newConcurrentMap(); //maps port numbers to peer to which the tunnel connects to.
        public Map<String,List<String>> PeerNameToFaceNames = Maps.newConcurrentMap();

    }

    private DeviceId getMasterSwitch(){
        List<String> devIds = new ArrayList<>(gatewaySwitchMap.keySet());
        Collections.sort(devIds);
        DeviceId master_new = DeviceId.deviceId(devIds.get(0));
        if (!master_new.equals(masterSwitchId)){
            //New switch will be gateway switch, need to flush all the rules, start from a clean slate.
            refreshFlows(master_new);
            //also refresh the old master
            refreshFlows(masterSwitchId);
            log.info(String.format("Master changed from %s to %s",
                    masterSwitchId, master_new));
        }
        return master_new;
    }

    private void refreshFlows(DeviceId deviceId){
        Iterable<FlowEntry> I = flowRuleService.getFlowEntriesById(appId);
        for (FlowEntry F:I){
            if (F.deviceId().equals(deviceId)){
                flowRuleService.removeFlowRules(F);
            }

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
            String peerGwID = null;
            PortNumber portNum = null;
            DeviceId gatewaySwitchId = event.subject().id();
            switch(event.type())
            {
                case DEVICE_ADDED:
                    event.subject();
                    log.info(String.format("Gateway switch with ID %s has been ADDED",gatewaySwitchId.toString()));
                    if (!gatewaySwitchMap.containsKey(gatewaySwitchId.toString()))
                        gatewaySwitchMap.put(gatewaySwitchId.toString(), new GatewaySwitch(gatewaySwitchId.toString()));
                    masterSwitchId = getMasterSwitch();
                    break;

                case DEVICE_REMOVED:
                    log.info(String.format("Gateway switch with ID %s has been REMOVED",gatewaySwitchId.toString()));
                    if (gatewaySwitchMap.containsKey(gatewaySwitchId.toString()))
                        gatewaySwitchMap.remove(gatewaySwitchId.toString());
                    masterSwitchId = getMasterSwitch();
                    break;
                case DEVICE_AVAILABILITY_CHANGED:
                    log.info(String.format("Gateway switch with ID %s has AVAILABILITY_CHANGED",gatewaySwitchId.toString()));
                    if (!gatewaySwitchMap.containsKey(gatewaySwitchId.toString()))
                        gatewaySwitchMap.put(gatewaySwitchId.toString(), new GatewaySwitch(gatewaySwitchId.toString()));
                    if (deviceService.isAvailable(gatewaySwitchId)==true) {
                        if (!gatewaySwitchMap.containsKey(gatewaySwitchId.toString()))
                            gatewaySwitchMap.put(gatewaySwitchId.toString(), new GatewaySwitch(gatewaySwitchId.toString()));
                        log.info(String.format("Switch %s is now ONLINE", gatewaySwitchId.toString()));
                    } else {
                        if (gatewaySwitchMap.containsKey(gatewaySwitchId.toString()))
                            gatewaySwitchMap.remove(gatewaySwitchId.toString());
                        log.info(String.format("Switch %s is now OFFLINE",gatewaySwitchId.toString()));
                    }
                    masterSwitchId = getMasterSwitch();
                    break;
                case DEVICE_UPDATED:
                    log.info(String.format("Gateway switch with ID %s has been UPDATED",gatewaySwitchId.toString()));
                    if (!gatewaySwitchMap.containsKey(gatewaySwitchId.toString()))
                        gatewaySwitchMap.put(gatewaySwitchId.toString(), new GatewaySwitch(gatewaySwitchId.toString()));
                    masterSwitchId = getMasterSwitch();
                    break;
                case PORT_ADDED:
                    portName = event.port().annotations().value("portName");
                    peerGwID = portName.split("@")[0];
                    portMac = event.port().annotations().value("portMac");
                    portNum = event.port().number();
                    log.info(event.subject().toString());
                    log.info(String.format("PORT ADDED %s, %s at %s",
                            portMac, portName, gatewaySwitchId.toString()));
                    if (!gatewaySwitchMap.get(gatewaySwitchId.toString()).PeerNameToFaceNames.containsKey(peerGwID)){
                        gatewaySwitchMap.get(gatewaySwitchId.toString()).PeerNameToFaceNames
                                .put(peerGwID, new LinkedList<String>());
                    }
                    gatewaySwitchMap.get(gatewaySwitchId.toString()).PeerNameToFaceNames
                            .get(peerGwID)
                            .add(portName);
                    gatewaySwitchMap.get(gatewaySwitchId.toString()).face_to_MacAndPort.put(portName,
                            new MacAndPort(MacAddress.valueOf(portMac),portNum,false));
                    gatewaySwitchMap.get(gatewaySwitchId.toString()).portToPeer.putIfAbsent(portNum,peerGwID);
                    break;
                case PORT_REMOVED:
                    portName = event.port().annotations().value("portName");
                    peerGwID = portName.split("@")[0];
                    portMac = event.port().annotations().value("portMac");
                    portNum = event.port().number();
                    log.info(event.subject().toString());
                    log.info(String.format("PORT REMOVED %s, %s at %s",
                            portMac, portName, gatewaySwitchId.toString()));
                    GatewaySwitch gs = gatewaySwitchMap.get(gatewaySwitchId.toString());
                    gs.face_to_MacAndPort.remove(portName);
                    gs.PeerNameToFaceNames.get(peerGwID).remove(portName);
                    if (gs.clo_port.containsKey(portNum))
                        gs.clo_port.remove(portNum);
                    gatewaySwitchMap.get(gatewaySwitchId.toString()).portToPeer.remove(portNum);
                    break;
                    /**
                     * if the devices disconnects and connects back it appears with a new device ID,
                     * the ports on the device are not ADDED rather UPDATED
                     * */
                case PORT_UPDATED:
                    portName = event.port().annotations().value("portName");
                    portMac = event.port().annotations().value("portMac");
                    portNum = event.port().number();
                    peerGwID = portName.split("@")[0];
                    log.info(event.subject().toString());
                    log.info(String.format("PORT UPDATED %s, %s at %s",
                            portMac, portName, gatewaySwitchId.toString()));
                    if (!gatewaySwitchMap.get(gatewaySwitchId.toString()).PeerNameToFaceNames.containsKey(peerGwID)){
                        gatewaySwitchMap.get(gatewaySwitchId.toString()).PeerNameToFaceNames
                                .put(peerGwID, new LinkedList<String>());
                    }
                    gatewaySwitchMap.get(gatewaySwitchId.toString()).PeerNameToFaceNames
                            .get(peerGwID)
                            .add(portName);
                    gatewaySwitchMap.get(gatewaySwitchId.toString()).face_to_MacAndPort.put(portName,
                            new MacAndPort(MacAddress.valueOf(portMac),portNum,false));
                    gatewaySwitchMap.get(gatewaySwitchId.toString()).portToPeer.putIfAbsent(portNum,peerGwID);
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
    private Ethernet createArpResponse(ConnectPoint cp, PacketContext pc, Ip4Address ipaddress) {
        MacAddress switch_mac = MacAddress.valueOf(getMacAddress(cp));
        Ethernet request = pc.inPacket().parsed();
        //Ip4Address srcIP = Ip4Address.valueOf("10.0.1.1");
        //MacAddress srcMac = MacAddress.valueOf("A9:DC:3C:F1:6A:0B");
        Ethernet arpReply = ARP.buildArpReply(ipaddress, switch_mac, request);
        return arpReply;

    }

    private Ethernet sendArpRequest(ConnectPoint cp, String ip_address)
    {
        MacAddress switch_mac = MacAddress.valueOf(getMacAddress(cp));
        byte[] senderMacAddress = switch_mac.toBytes();
        byte[] senderIpAddress = gatewaySwitchMap.get(cp.deviceId().toString()).ipAddress.toOctets();
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

    /**
     * This is to associate an IP address with an outgoing MAC and PORT on the CLO
     * address recieved is mapped address, GM will reply to ARP request for this address
     * */
    public void populate_arped_addresseses(String address, String peerGwID){
        for (GatewaySwitch gs:gatewaySwitchMap.values()) {
            if (!gs.PeerNameToFaceNames.containsKey(peerGwID))
                continue;
            for (String face_name : gs.PeerNameToFaceNames.get(peerGwID)) {
                MacAddress mac = gs.face_to_MacAndPort.containsKey(face_name) ?
                        gs.face_to_MacAndPort.get(face_name).MAC : null;
                PortNumber port = gs.face_to_MacAndPort.containsKey(face_name) ?
                        gs.face_to_MacAndPort.get(face_name).PORT : null;
                if (mac == null) {
                    log.error(String.format("NO MAC mapping for %s" +
                            "on switch %s", face_name, gs.switchID));
                    continue;
                }
                if (port == null) {
                    log.error(String.format("NO PORT mapping for %s" +
                            "on switch %s", face_name, gs.switchID));
                    continue;
                }
                if (!gs.ip4_to_MacAndPort.containsKey(Ip4Address.valueOf(address)))
                    gs.ip4_to_MacAndPort.put(Ip4Address.valueOf(address), new HashSet<MacAndPort>());
                gs.ip4_to_MacAndPort.get(Ip4Address.valueOf(address)).add(new MacAndPort(mac, port, false));
                /* TODO clear out the map*/
                // keep track of clo ports.
                if (!gs.clo_port.containsKey(port))
                    gs.clo_port.put(port, true);
                populate_arped_candidates(Ip4Address.valueOf(address));
            }
        }
    }


    /**
     * Want controller to start sending our ARP request for these addresses.
     * @param address
     */
    public void initiate_arp_requests(String address){
    }
    /**
     * if incoming is true - make a remote to mapped mapping
     * if incoming is false/outgoing on CLO - make a mapped to remote mapping
     * */
    public void translate_address(String match_address, String new_address, Boolean incoming,
                                  String match_social_id,
                                  String new_social_id){
        endpoint match = new endpoint(match_address, match_social_id);
        endpoint  matched = new endpoint(new_address, new_social_id);
        if (incoming==false) {
            x_mapped_rem.putIfAbsent(match,matched);
        }
        else {
            x_rem_mapped.putIfAbsent(match,matched);
        }

    }

    /** port binds to tunnel, one for each CLO peer tunnel
    * address binds to device, allow access to device
    * for incoming traffic from this port on gateway switches.*/
    public void allow_access(String peerGWID, String address) {
        for (GatewaySwitch gw_switch : gatewaySwitchMap.values()) {
            if (!gw_switch.PeerNameToFaceNames.containsKey(peerGWID))
                continue;
            for (String face_name:gw_switch.PeerNameToFaceNames.get(peerGWID)) {
                PortNumber port = gw_switch.face_to_MacAndPort.containsKey(face_name) ?
                        gw_switch.face_to_MacAndPort.get(face_name).PORT : null;
                if (port == null) {
                    log.error(String.format("No port found corresponding to face %s" +
                            " on switch %s", face_name, gw_switch.switchID));
                } else {
                    if (!gw_switch.access_map.containsKey(Ip4Address.valueOf(address))) {
                        gw_switch.access_map.put(Ip4Address.valueOf(address), new LinkedList<>());
                    }
                    List<PortNumber> accessList = gw_switch.access_map.get(Ip4Address.valueOf(address));
                    accessList.add(port);
                }
            }
        }
    }

    public void remove_arped_candidates(String address){
        // will have to handle removal
    }


    public void do_something()
    {
        //log.info("Doing something ha ha ha");
    }

    public String get_mapped_to_remote(String mapped_address, String SocialPeer){
        endpoint q = new endpoint(mapped_address, SocialPeer);
        endpoint t = x_mapped_rem.getOrDefault(q,null);
        return t==null?null:t.ipaddress.toString();
    }

    /* Need to populate gateway switches in the system*/
    public void getDevices(){
        Iterable<Device> I = deviceService.getAvailableDevices(Device.Type.SWITCH);
        for (Device D: I){
            String switchID = D.id().toString();
            log.info("Switch detected with Id"+switchID);
            if (!gatewaySwitchMap.containsKey(switchID)){
                GatewaySwitch gatewaySwitch = new GatewaySwitch(switchID);
                gatewaySwitchMap.put(switchID, gatewaySwitch);
                List<Port> portList = deviceService.getPorts(D.id());
                for (Port p: portList){
                    String pName = p.annotations().value("portName");
                    String peerGwID = pName.split("@")[0];
                    MacAddress pMac = MacAddress.valueOf(p.annotations().value("portMac"));
                    PortNumber pNum = p.number();
                    log.info(String.format("\n Interface %s MAC %s PORT %s at %s\n"
                    ,pName,pMac.toString(),pNum.name(),switchID));
                    //if already there just overwrite
                    if (!gatewaySwitchMap.get(switchID.toString()).PeerNameToFaceNames.containsKey(peerGwID)){
                        gatewaySwitchMap.get(switchID.toString()).PeerNameToFaceNames
                                .put(peerGwID, new LinkedList<String>());
                    }
                    gatewaySwitchMap.get(switchID.toString()).PeerNameToFaceNames
                            .get(peerGwID)
                            .add(pName);
                    gatewaySwitchMap.get(switchID.toString()).face_to_MacAndPort.put(pName,
                            new MacAndPort(pMac,pNum,false));
                    gatewaySwitchMap.get(switchID.toString()).portToPeer.putIfAbsent(pNum,peerGwID);
                    /* TODO : ONLY FOR TESTING */
                    if (pName.startsWith("perso_")){
                        gatewaySwitch.clo_port.put(pNum,true);
                    }

                }
            }
        }
    }
}
