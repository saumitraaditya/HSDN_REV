package org.onosproject.osnBridge.rest;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.onosproject.rest.AbstractWebResource;
import org.slf4j.Logger;
import javax.ws.rs.*;
import javax.ws.rs.core.Response;

import static org.slf4j.LoggerFactory.getLogger;

@Path("/")
public class WebResource extends AbstractWebResource {

    private final Logger log = getLogger(getClass());

    @GET
    @Path("/test")
    public Response getTest()
    {
        ObjectNode responseBody = new ObjectNode(JsonNodeFactory.instance);
        responseBody.put("message","test on osnBridge_service works !!!");
        return Response.status(200).entity(responseBody).build();
    }


}

