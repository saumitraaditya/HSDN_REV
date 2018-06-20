package org.onosproject.socialGateway;

import org.onlab.packet.Ip4Address;

public interface gatewayService {
    public void do_something();
    public void allow_access(String admin, String address);
    public void populate_arped_addresseses(String address, String face_name);
    public void translate_address(String match_address, String new_address, Boolean incoming);
    public void initiate_arp_requests(String address);
    public Ip4Address find_free_address();
    public String get_mapped_to_remote(String mapped_address);
}
