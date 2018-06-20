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


    String setup = "setup";
    String query = "query";
    String resp = "resp";
    String tag = "tag";



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

    public void set_interfaces(String _setup, String _query, String _resp,String _tag)
    {
        this.setup = _setup;
        this.query = _query;
        this.resp = _resp;
        this.tag = _tag;
    }

    public ArrayList<String> get_interfaces()
    {
        ArrayList<String> interfaces = new ArrayList<>();
        interfaces.add(this.setup);
        interfaces.add(this.query);
        interfaces.add(this.resp);
        interfaces.add(this.tag);

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
            DNS_ext.set_interfaces(interfaceMap.get(SETUP), interfaceMap.get(QUERY), interfaceMap.get(RESPONSE),interfaceMap.get(TAG));
            return DNS_ext;
        }

    }

}
