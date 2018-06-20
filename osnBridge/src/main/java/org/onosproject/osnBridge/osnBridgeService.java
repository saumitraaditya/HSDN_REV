package org.onosproject.osnBridge;

public interface osnBridgeService {

    //public void send(String target,  String query);

    public void send(String target, String setup, String query, String response, String tag);

}
