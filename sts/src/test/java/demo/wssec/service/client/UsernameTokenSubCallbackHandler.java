package demo.wssec.service.client;
import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.springframework.beans.factory.annotation.Value;

import demo.wssec.service.common.ISubCallbackHandler;

/**
 * Handle the WSPasswordCallback USERNAME_TOKEN. This is used by
 * SAML2stsSubCallbackHandler in order share a symmetric bindings.
 */
public class UsernameTokenSubCallbackHandler implements ISubCallbackHandler {
    
	@Value("${client.user}")
    private String clientUser;

    @Value("${client.user.password}")
    private String userPassword;

	@Override
	public boolean canHandle(Callback pCallback) {
		return pCallback instanceof WSPasswordCallback
				&& ((WSPasswordCallback) pCallback).getUsage() == WSPasswordCallback.USERNAME_TOKEN;
	}

        
        /**
         * used by the client to inject users password
         * @param pCallback
         * @throws IOException
         * @throws UnsupportedCallbackException 
         */
	@Override
	public void handle(Callback pCallback) throws IOException,
			UnsupportedCallbackException {
		WSPasswordCallback wsPasswordCallback = (WSPasswordCallback) pCallback;

		if (clientUser.equals(wsPasswordCallback.getIdentifier())) {
			wsPasswordCallback.setPassword(userPassword);
		}
	}

}