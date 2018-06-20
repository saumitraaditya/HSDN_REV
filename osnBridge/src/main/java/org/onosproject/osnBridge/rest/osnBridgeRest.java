package org.onosproject.osnBridge.rest;
import org.onlab.rest.AbstractWebApplication;
import java.util.Set;

public class osnBridgeRest extends AbstractWebApplication {

    @Override
    public Set<Class<?>> getClasses()
    {
        return getClasses(WebResource.class);
    }
}