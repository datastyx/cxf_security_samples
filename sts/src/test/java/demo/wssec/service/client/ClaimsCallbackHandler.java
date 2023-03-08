package demo.wssec.service.client;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.apache.cxf.helpers.DOMUtils;
import org.apache.cxf.ws.security.trust.claims.ClaimsCallback;

/**
 * This CallbackHandler implementation creates a Claims Element for a "role" ClaimType and
 * stores it on the ClaimsCallback object.
 */
public class ClaimsCallbackHandler implements CallbackHandler {
    
    public void handle(Callback[] callbacks)
        throws IOException, UnsupportedCallbackException {
        for (int i = 0; i < callbacks.length; i++) {
            if (callbacks[i] instanceof ClaimsCallback) {
                ClaimsCallback callback = (ClaimsCallback) callbacks[i];
                callback.setClaims(createClaims());
                
            } else {
                throw new UnsupportedCallbackException(callbacks[i], "Unrecognized Callback");
            }
        }
    }
    
    /**
     * Create a Claims Element for a "role"
     */
    private Element createClaims() {
        Document doc = DOMUtils.createDocument();
        Element claimsElement = 
            doc.createElementNS("http://docs.oasis-open.org/ws-sx/ws-trust/200512", "Claims");
        claimsElement.setAttributeNS(null, "Dialect", ClaimConstant.CLAIMS_DIALECT);
//        emailaddress claim
        Element emailAddressClaimType = 
            doc.createElementNS(ClaimConstant.CLAIMS_DIALECT, "ClaimType");
        emailAddressClaimType.setAttributeNS(null, "Uri", ClaimConstant.EMAIL_ADDRESS_CLAIM.getURI().toString());
        claimsElement.appendChild(emailAddressClaimType);

        return claimsElement;
    }
}