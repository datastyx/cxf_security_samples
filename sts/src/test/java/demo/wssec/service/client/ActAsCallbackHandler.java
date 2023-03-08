package demo.wssec.service.client;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.cxf.ws.security.trust.delegation.DelegationCallback;
import org.apache.wss4j.common.WSS4JConstants;
import org.w3c.dom.Element;

import demo.wssec.sts.DelegateSAML2AssertionTest;

/**
 * This CallbackHandler implementation intends to extract a SAML2.0 assertion
 * from the current securityContext.
 */
public class ActAsCallbackHandler implements CallbackHandler {

    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        for (int i = 0; i < callbacks.length; i++) {
            if (callbacks[i] instanceof DelegationCallback) {
                try {
                  DelegateSAML2AssertionTest delegateSAML2AssertionTest = new DelegateSAML2AssertionTest();
                  Element saml2assertion = delegateSAML2AssertionTest.getSAMLAssertion(WSS4JConstants.WSS_SAML2_TOKEN_TYPE);

                    DelegationCallback callback = (DelegationCallback) callbacks[i];

                    callback.setToken(saml2assertion);
                } catch ( Exception e) {
                    throw new UnsupportedCallbackException(callbacks[i], e.getLocalizedMessage());
                }
            } else {
                throw new UnsupportedCallbackException(callbacks[i], "Unrecognized Callback");
            }
        }
    }
}
