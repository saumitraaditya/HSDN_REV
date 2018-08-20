package org.onosproject.osnBridge;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.jivesoftware.smack.packet.ExtensionElement;
import org.jivesoftware.smack.provider.EmbeddedExtensionProvider;
import org.jivesoftware.smack.util.XmlStringBuilder;

public class DNS_Extension implements ExtensionElement
{
    static final String NS = "DNS_setup";
    static final String EL = "DNS";
    static final String SETUP = "setup";
    static final String QUERY = "query";
    static final String RESPONSE = "resp";
    static final String TAG = "tag";
    static final String RES_PATH = "res_path";
    static final String HOP = "hop_count";


    String setup = "setup";
    String query = "query";
    String resp = "resp";
    String tag = "tag";
    String res_path = "res_path";
    String hop_count = "hop_count";



    public String getElementName() {
        // TODO Auto-generated method stub
        return EL;
    }

    public CharSequence toXML() {
        // TODO Auto-generated method stub
        XmlStringBuilder xml = new XmlStringBuilder(this);
        xml.attribute(SETUP, get_setup());
        xml.attribute(QUERY, get_query());
        xml.attribute(RESPONSE, get_resp());
        xml.attribute(TAG,get_tag());
        xml.attribute(RES_PATH,get_res_path());
        xml.attribute(HOP,get_hop_count());
        xml.closeEmptyElement();
        return xml;
    }

    public String get_setup()
    {
        return setup;
    }

    public String get_query()
    {
        return query;
    }

    public String get_resp()
    {
        return resp;
    }
    public String getNamespace() {
        // TODO Auto-generated method stub
        return NS;
    }

    public String get_tag(){return tag;}

    public String get_res_path(){return res_path;}

    public String get_hop_count(){return hop_count;}

    public void set_interfaces(String _setup, String _query, String _resp,String _tag, String _res_path, String _hop_count)
    {
        this.setup = _setup;
        this.query = _query;
        this.resp = _resp;
        this.tag = _tag;
        this.res_path = _res_path;
        this.hop_count = _hop_count;
    }

    public ArrayList<String> get_interfaces()
    {
        ArrayList<String> interfaces = new ArrayList<>();
        interfaces.add(this.setup);
        interfaces.add(this.query);
        interfaces.add(this.resp);
        interfaces.add(this.tag);
        interfaces.add(this.res_path);
        interfaces.add(this.hop_count);

        return interfaces;
    }

    public static class Provider extends EmbeddedExtensionProvider<DNS_Extension>
    {

        @Override
        protected DNS_Extension createReturnExtension(String EL, String NS, Map<String, String> interfaceMap,
                                                      List<? extends ExtensionElement> content) {
            // TODO Auto-generated method stub
            System.out.println("Here");
            DNS_Extension DNS_ext = new DNS_Extension();
            DNS_ext.set_interfaces(interfaceMap.get(SETUP), interfaceMap.get(QUERY),
                    interfaceMap.get(RESPONSE),interfaceMap.get(TAG),
                    interfaceMap.get(RES_PATH),
                    interfaceMap.get(HOP));
            return DNS_ext;
        }

    }

}
