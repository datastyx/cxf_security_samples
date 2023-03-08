package demo.wssec.service.client;

import org.apache.cxf.ws.security.SecurityConstants;
import org.apache.cxf.ws.security.tokenstore.SecurityToken;
import org.apache.cxf.ws.security.trust.STSClient;
import org.apache.wss4j.common.saml.SAMLCallback;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;

//import org.apache.cxf.sts.STSConstants;

/**
 * This is used to handle the custom token and get a SAML 2 token.
 */
public class SAML2stsCallbackHandler implements CallbackHandler {

	/**
	 * Logger of the class.
	 */
	private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory
			.getLogger(SAML2stsCallbackHandler.class);

	/**
	 * STS client.
	 */
	private STSClient stsClient;

	/**
	 * Target STS web service address
	 */
	private final String stsServiceAddress;

	public SAML2stsCallbackHandler(final String pStsServiceAddress) {
		stsServiceAddress = pStsServiceAddress;
	}

	public void setStsClient(STSClient stsClient) {
		this.stsClient = stsClient;
	}

	public void setSamlCallbackHandler(CallbackHandler pCallbackHandler) {
		stsClient.getProperties().put(SecurityConstants.SAML_CALLBACK_HANDLER,
				pCallbackHandler);
	}

	@Override
	public void handle(Callback[] pCallbacks) throws IOException,
			UnsupportedCallbackException {
		for (Callback callback : pCallbacks) {
			if (callback instanceof SAMLCallback) {
				SecurityToken st = null;
				try {
					if (LOGGER.isInfoEnabled()) {
						LOGGER.info("Retrieving a STS token");
					}
					st = stsClient.requestSecurityToken(stsServiceAddress);
					
					((SAMLCallback) callback)
							.setAssertionElement(st.getToken());
				} catch (Exception ex) {
					LOGGER.error(null, ex);
					//ClientMain.getInstance().notifyException(Thread.currentThread(), new Exception("STS connexion failed.\n"));
					throw new RuntimeException(new Exception("STS connexion failed with message : " + ex.getMessage()));
				}
				if (LOGGER.isInfoEnabled()) {
					LOGGER.info("Token set");
				}
			}
		}
	}
}