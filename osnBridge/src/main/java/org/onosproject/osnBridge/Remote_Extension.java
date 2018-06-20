package org.onosproject.osnBridge;

import org.jivesoftware.smack.packet.ExtensionElement;
import org.jivesoftware.smack.provider.EmbeddedExtensionProvider;
import org.jivesoftware.smack.util.XmlStringBuilder;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class Remote_Extension implements ExtensionElement {

    static final String NS = "remote";
    static final String EL = "remote";
    static final String SETUP = "setup";
    static final String TYPE = "type";
    static final String PAYLOAD = "payload";



    String setup = "setup";
    String type = "type";
    String payload = "payload";




    public String getElementName() {
        // TODO Auto-generated method stub
        return EL;
    }

    public CharSequence toXML() {
        // TODO Auto-generated method stub
        XmlStringBuilder xml = new XmlStringBuilder(this);
        xml.attribute(SETUP, get_setup());
        xml.attribute(TYPE, get_type());
        xml.attribute(PAYLOAD, get_payload());
        xml.closeEmptyElement();
        return xml;
    }

    public String get_setup()
    {
        return setup;
    }

    public String get_type()
    {
        return type;
    }

    public String get_payload()
    {
        return payload;
    }
    public String getNamespace() {
        // TODO Auto-generated method stub
        return NS;
    }



    public void set_interfaces(String _setup, String _type, String _payload)
    {
        this.setup = _setup;
        this.type = _type;
        this.payload = _payload;
    }

    public ArrayList<String> get_interfaces()
    {
        ArrayList<String> interfaces = new ArrayList<>();
        interfaces.add(this.setup);
        interfaces.add(this.type);
        interfaces.add(this.payload);
        return interfaces;
    }

    public static class Provider extends EmbeddedExtensionProvider<Remote_Extension>
    {

        @Override
        protected Remote_Extension createReturnExtension(String EL, String NS, Map<String, String> interfaceMap,
                                                      List<? extends ExtensionElement> content) {
            // TODO Auto-generated method stub
            System.out.println("Here");
            Remote_Extension Remote_ext = new Remote_Extension();
            Remote_ext.set_interfaces(interfaceMap.get(SETUP), interfaceMap.get(TYPE), interfaceMap.get(PAYLOAD));
            return Remote_ext;
        }

    }
}
