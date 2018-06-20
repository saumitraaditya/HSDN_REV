package org.onosproject.osnBridge;

import com.fasterxml.jackson.databind.JsonNode;
import org.onosproject.core.ApplicationId;
import org.onosproject.net.config.Config;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class osnBridgeConfig extends Config<ApplicationId> {

    private final Logger log = LoggerFactory.getLogger(getClass());
    private static final String CONFIG = "socialConfig";
    private static final String CLO_SOCIAL_ID = "CLOSocialId";
    private static final String PLO_SOCIAL_ID = "PLOSocialId";
    private static final String CLO_SOCIAL_SERVER = "CLOSocialServer";
    private static final String CLO_SOCIAL_PASSWORD = "CLOSocialPassword";

    public socialGatewayNode getConfig(){
        JsonNode jsonNode = object.path(CONFIG);
        return new socialGatewayNode(jsonNode.path(CLO_SOCIAL_ID).textValue(),
                jsonNode.path(PLO_SOCIAL_ID).textValue(),
                jsonNode.path(CLO_SOCIAL_SERVER).textValue(),
                jsonNode.path(CLO_SOCIAL_PASSWORD).textValue());
    }

    public static class socialGatewayNode{
        public String CLOSocialId;
        public String PLOSocialId;
        public String CLOSocialServer;
        public String CLOSocialPassword;

        public socialGatewayNode(String CLOSocialId,
                                 String PLOSocialId,
                                 String CLOSocialServer,
                                 String CLOSocialPassword){
            this.CLOSocialId = CLOSocialId;
            this.PLOSocialId = PLOSocialId;
            this.CLOSocialServer = CLOSocialServer;
            this.CLOSocialPassword = CLOSocialPassword;

        }

        public String displayConfig(){
            return ("CLOSocialId: "+this.CLOSocialId+
            "\n PLOSocialId: "+ this.PLOSocialId+
            "\n CLOSocialServer: "+this.CLOSocialServer+
            "\n CLOSocialPassword: "+this.CLOSocialPassword);
        }
    }
}
