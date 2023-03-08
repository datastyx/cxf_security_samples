package demo.wssec.service.client;

import java.net.URI;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public enum ClaimConstant {

    ROLE_CLAIM("/claims/role"),
    EMAIL_ADDRESS_CLAIM("/claims/emailaddress"),
    COUNTRY_CLAIM("/claims/country"),
    CLEARANCE_CLAIM(URI.create("http://cwix.act.nato.int/clearance"));

    public final static String CLAIMS_DIALECT = "http://schemas.xmlsoap.org/ws/2005/05/identity";

    public final static String ENVIRONMENT_ATTRIBUTE = "http://cwix.act.nato.int/environment";

    private final static Map<String, ClaimConstant> uriStringsToClaimContants = Collections.unmodifiableMap(initializeMapping());

    private URI uri;

    ClaimConstant(String claimURI) {
        uri = URI.create(ClaimConstant.CLAIMS_DIALECT + claimURI);
    }

    ClaimConstant(URI claimURI) {
        uri = claimURI;
    }

    public URI getURI() {
        return uri;
    }

    public static ClaimConstant getClaimConstant(String uriString) {
        return uriStringsToClaimContants.get(uriString);
    }

    private static Map<String, ClaimConstant> initializeMapping() {
        Map<String, ClaimConstant> tempMap = new HashMap<String, ClaimConstant>();
        for (ClaimConstant claimConstant : ClaimConstant.values()) {
            tempMap.put(claimConstant.uri.toString(), claimConstant);

        }
        return tempMap;
    }
}
