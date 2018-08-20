

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
        package org.onosproject.osnBridge;
        import com.google.common.collect.Maps;
        import com.google.common.collect.Sets;
        import io.netty.util.concurrent.SingleThreadEventExecutor;
        import org.apache.felix.scr.annotations.Component;
        import org.apache.felix.scr.annotations.Service;
        import org.apache.felix.scr.annotations.Activate;
        import org.apache.felix.scr.annotations.Deactivate;
        import org.apache.felix.scr.annotations.ReferenceCardinality;
        import org.apache.felix.scr.annotations.Reference;
        import org.jivesoftware.smack.chat2.Chat;
        import org.jivesoftware.smack.chat2.ChatManager;
        import org.jxmpp.jid.EntityBareJid;
        import org.jxmpp.jid.Jid;
        import org.jxmpp.jid.impl.JidCreate;
        import org.onlab.packet.IP;
        import org.onlab.packet.IpAddress;
        import org.onlab.packet.TpPort;
        import org.onlab.util.ItemNotFoundException;
        import org.onosproject.cluster.ClusterService;
        import org.onosproject.core.ApplicationId;
        import org.onosproject.core.CoreService;


        import org.onosproject.net.config.*;
        import org.onosproject.net.config.basics.SubjectFactories;
        import org.onosproject.net.device.DeviceAdminService;
        import org.onosproject.net.driver.DriverService;
        import org.onosproject.socialGateway.gatewayService;
        import org.slf4j.Logger;
        import org.slf4j.LoggerFactory;
        import java.util.ArrayList;
        import java.util.HashSet;
        import java.util.List;
        import java.util.Map;
        import java.util.Set;

        import java.util.concurrent.ExecutorService;
        import java.util.Optional;
        import java.util.NoSuchElementException;
        import java.util.concurrent.atomic.AtomicLong;

        import static java.util.concurrent.Executors.unconfigurableExecutorService;
        import static org.onlab.util.Tools.isNullOrEmpty;
        import static java.util.concurrent.Executors.newSingleThreadExecutor;
        import static org.onlab.util.Tools.groupedThreads;

        import org.jivesoftware.smack.XMPPConnection;
        import org.jivesoftware.smack.XMPPException;
        import org.jivesoftware.smack.filter.StanzaExtensionFilter;
        import org.jivesoftware.smack.filter.StanzaFilter;
        import org.jivesoftware.smack.packet.ExtensionElement;
        import org.jivesoftware.smack.packet.Message;
        import org.jivesoftware.smack.packet.Stanza;
        import org.jivesoftware.smack.provider.EmbeddedExtensionProvider;
        import org.jivesoftware.smack.provider.ProviderManager;
        import org.jivesoftware.smack.tcp.XMPPTCPConnection;
        import org.jivesoftware.smack.tcp.XMPPTCPConnectionConfiguration;
        import org.jivesoftware.smack.util.XmlStringBuilder;
        import org.jxmpp.stringprep.XmppStringprepException;
        import org.jivesoftware.smack.AbstractXMPPConnection;
        import org.jivesoftware.smack.ConnectionConfiguration;
        import org.jivesoftware.smack.SmackException;
        import org.jivesoftware.smack.StanzaCollector;
        import org.jivesoftware.smack.StanzaListener;
        import java.io.IOException;



/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true,enabled=true)
public class osnBridgeManager implements osnBridgeService{

    private final Logger log = LoggerFactory.getLogger(getClass());
    private ApplicationId appId;
    private static final int DPID_BEGIN = 4;
    private static final int OFPORT = 6653;
    protected Map<String, String> tag_sender = Maps.newConcurrentMap();
    protected Map<String, String> dns_path = Maps.newConcurrentMap();

    XMPPTCPConnectionConfiguration config;
    AbstractXMPPConnection conn;
    StanzaFilter filter;
    StanzaCollector collector;
    StanzaListener listener;



    @Reference(cardinality=ReferenceCardinality.MANDATORY_UNARY)
    protected CoreService coreService;


    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected gatewayService GatewayService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected NetworkConfigRegistry configRegistry;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected NetworkConfigService configService;

    /*
    * maintain a cache of IP addresses allocated to remote devices
    *
    *
    * */
    private Map<String, String> mapped_names = Maps.newConcurrentMap();


    private Thread thread;
    private volatile boolean xmpp_active = false;
    private osnBridgeConfig.socialGatewayNode socialInfo;

    private final ExecutorService eventExecutor = newSingleThreadExecutor(groupedThreads("onos/osnBridge",
            "event_handler",log));

    private final NetworkConfigListener configListener= new InternalConfigListener();

    private class InternalConfigListener implements NetworkConfigListener
    {
        @Override
        public void event (NetworkConfigEvent nevent)
        {
            if (!nevent.configClass().equals(osnBridgeConfig.class))
            {
                return;
            }
            switch(nevent.type())
            {
                case CONFIG_ADDED:
                case CONFIG_UPDATED:
                    eventExecutor.execute(osnBridgeManager.this::readConfiguration);
                    break;
                default:
                    break;
            }

        }
    }

    private final ConfigFactory configFactory = new ConfigFactory(SubjectFactories.APP_SUBJECT_FACTORY,osnBridgeConfig.class,
            "osnBridge_service") {
        @Override
        public osnBridgeConfig createConfig() {
            return new osnBridgeConfig();
        }
    };

    private void readConfiguration()
    {
        if (this.appId == null)
            log.debug("Null app ID");
        osnBridgeConfig config = configRegistry.getConfig(this.appId,osnBridgeConfig.class);
        if (config == null)
        {
            log.error("No configuration found.");
            return;
        }
        this.socialInfo = config.getConfig();
        log.info("Loaded social coniguration is as follows:+\n"+socialInfo.displayConfig());
        thread = new Thread(new xmpp_initializer());
        thread.start();
    }

    @Activate
    public void activate() {
        log.info("XmppAgent started");
        appId = coreService.getAppId("org.onosproject.osnBridge");
        configService.addListener(configListener);
        configRegistry.registerConfigFactory(configFactory);
//        try
//        {
//            initialize_xmpp();
//        }
//        catch (Exception e)
//        {
//            log.info(e.toString());
//        }
//        thread = new Thread(new xmpp_initializer());
//        thread.start();


    }

    @Deactivate
    public void deactivate() {
        xmpp_active = false;
        configService.removeListener(configListener);
        configRegistry.unregisterConfigFactory(configFactory);
        eventExecutor.shutdown();
    }

    public void send(String to, String setup, String query, String response, String tag, String res_path, String hop_no)
    {
        Message message = new Message();
        message.setType(Message.Type.chat);
        DNS_Extension dns_extension = new DNS_Extension();
        dns_extension.set_interfaces(setup,query,response,tag,res_path, hop_no);
        message.addExtension(dns_extension);
        ChatManager chatManager = ChatManager.getInstanceFor(conn);
        try {
            EntityBareJid jid = JidCreate.entityBareFrom(to);
            Chat chat = chatManager.chatWith(jid);
            chat.send(message);
        } catch (Exception e)
        {
            log.info(e.toString());
        }

    }

    public void sendRemote(String to, String setup, String type, String payload){
        Message message = new Message();
        message.setType(Message.Type.chat);
        Remote_Extension remote_extension = new Remote_Extension();
        remote_extension.set_interfaces(setup, type, payload);
        message.addExtension(remote_extension);
        ChatManager chatManager = ChatManager.getInstanceFor(conn);
        try {
            EntityBareJid jid = JidCreate.entityBareFrom(to);
            Chat chat = chatManager.chatWith(jid);
            chat.send(message);
        } catch (Exception e)
        {
            log.info(e.toString());
        }

    }

    public void handle(DNS_Extension dns_extension, String sender)
    {
        String setup = dns_extension.get_setup();
        String query = dns_extension.get_query();
        String target_recipient = query.split("\\.")[1];
        String tag = dns_extension.get_tag();
        String response = dns_extension.get_resp();
        String resPath = dns_extension.get_res_path();
        String hop = dns_extension.get_hop_count();

        switch(setup)
        {
            case "QUERY":
                tag_sender.putIfAbsent(tag,sender);
                if (dns_path.containsKey(target_recipient)){
                    String[] path = dns_path.get(target_recipient).split(":");
                    String NextHopRecipient = path[Integer.parseInt(hop)+1];
                    send(NextHopRecipient,"QUERY_IC",query,response,tag
                    ,dns_path.get(target_recipient),String.valueOf(Integer.parseInt(hop)+1));
                }
                break;
            case "RESP":
                break;
            case "QUERY_IC":
                /* need to do a name query to check availability and to get back IP address of the device*/
                tag_sender.putIfAbsent(tag,sender);
                /*
                not going to use dname to route queries, in new design only one inner social id for all devices
                String dname = query.split("\\.")[0];
                */
                if (target_recipient.equals(this.socialInfo.CLOSocialId)){
                    send(this.socialInfo.PLOSocialId,"NAME_QUERY",query,response,tag,
                            resPath, hop);
                } else{
                    String []path = dns_path.get(target_recipient).split(":");
                    String NextHopRecipient = path[Integer.parseInt(hop)+1];
                    send(NextHopRecipient,"QUERY_IC",query,response,tag
                            ,dns_path.get(target_recipient),String.valueOf(Integer.parseInt(hop)+1));
                }
                break;
            case "RESP_IC":
                String NextHop = tag_sender.get(tag);
                String mapped_addr;
                String remote_addr = response;
                String peerGWID = sender.split("@")[0];
                /**
                 *  populate arp addresses will
                 *  1. make the controller respond to arp requests for the mapped addresses.
                 *  2. map the mapped address to outgoing port and mac.
                 *  check if the mapped address is already in cache else allocate new addresss
                 *  TODO when to remove the entry from cache?
                 */
                if (mapped_names.containsKey(query)){
                    String cached_mapped_addr = mapped_names.get(query);
                    mapped_addr = GatewayService.get_mapped_to_remote(cached_mapped_addr, "PLO");
                    if (mapped_addr == null || !mapped_addr.equals(remote_addr)){
                        mapped_addr = GatewayService.find_free_address().toString();
                        mapped_names.remove(query);
                        mapped_names.put(query, mapped_addr);
                    }else{
                        mapped_addr = cached_mapped_addr;
                    }
                } else{
                    mapped_addr = GatewayService.find_free_address().toString();
                    mapped_names.put(query, mapped_addr);
                }
                GatewayService.populate_arped_addresseses(mapped_addr,peerGWID);
                GatewayService.translate_address(mapped_addr,remote_addr,false,
                        //this.socialInfo.CLOSocialId.split("@")[0],
                        "PLO",
                        peerGWID);
                GatewayService.translate_address(remote_addr,mapped_addr,true,
                        peerGWID,
                        //this.socialInfo.CLOSocialId.split("@")[0]);
                        "PLO");

                if (NextHop.equals(this.socialInfo.PLOSocialId))
                    send(NextHop,"RESP",query,mapped_addr,tag,resPath,hop);
                else
                    send(NextHop,"RESP_IC",query,mapped_addr,tag,resPath,hop);

                break;
            case "NAME_RESP":
                String sendto = tag_sender.get(tag);
                peerGWID = sendto.split("@")[0];
                GatewayService.allow_access(peerGWID,response);
                GatewayService.initiate_arp_requests(response);
                send(sendto,"RESP_IC",query,response,tag, resPath,hop);
                break;
        }
    }

    private class xmpp_initializer implements Runnable
    {
        public void run()
        {
            try
            {
                GatewayService.do_something();
                xmpp_active = true;
                initialize_xmpp();
            }
            catch (Exception e)
            {
                log.info(e.toString());
            }
        }
    }

    private void initialize_xmpp() throws SmackException, IOException, XMPPException, InterruptedException
    {
        config = XMPPTCPConnectionConfiguration.builder()
                .setUsernameAndPassword(this.socialInfo.CLOSocialId, this.socialInfo.CLOSocialPassword)
                .setXmppDomain(this.socialInfo.CLOSocialServer)
                .setPort(5222)
                .setSecurityMode(ConnectionConfiguration.SecurityMode.disabled)
                .addEnabledSaslMechanism("PLAIN")
                .build();
        conn = new XMPPTCPConnection(config);
        filter = new StanzaExtensionFilter(DNS_Extension.EL,DNS_Extension.NS);
        collector = conn.createStanzaCollector(filter);
        listener = new StanzaListener()
        {
            public void processStanza(Stanza stanza)
            {
                String msg = stanza.toString();
                Jid sender = stanza.getFrom().asBareJid();
                System.out.println(stanza.toXML());
                ExtensionElement ext = stanza.getExtension(DNS_Extension.NS);
                DNS_Extension dns_ext = (DNS_Extension) ext;
                //System.out.println(dns_ext.toXML());
                //System.out.println(dns_ext.toString());
                //dns_ext.get_interfaces();
                //System.out.println(msg);
                String query = dns_ext.get_query();
                log.info(dns_ext.toXML().toString());
                log.info(msg);
                //send(sender.toString(),"RESP",query,"127.0.0.1","747364346");
                handle(dns_ext,sender.toString());

            }
        };
        conn.addAsyncStanzaListener(listener,filter);
        ProviderManager.addExtensionProvider(DNS_Extension.EL, DNS_Extension.NS, new DNS_Extension.Provider());
        conn.connect();
        conn.login();
        //sendRemote("d1_bob_gnv@xmpp.ipop-project.org","GCC-ICC","command_connect","bob_gnv_gw@xmpp.ipop-project.org");
        //log.info("sent out a remote control");

//        while (xmpp_active)
//        {
//            continue;
//        }
    }



}

