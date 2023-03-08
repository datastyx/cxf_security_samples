package demo.wssec.service.common;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.wss4j.common.ext.WSPasswordCallback;

/**
 * Handle the case to access keystore which contains the private key.
 */
public class KeystoreSubCallbackHandler implements ISubCallbackHandler {

	/**
	 * Keystore password
	 */
	private final String keystorePassword;

	public KeystoreSubCallbackHandler(String pKeystorePassword) {
		keystorePassword = pKeystorePassword;
	}

	@Override
	public boolean canHandle(Callback pCallback) {
		boolean result = false;
		if (pCallback instanceof WSPasswordCallback) {
			WSPasswordCallback wsPasswordCallback = (WSPasswordCallback) pCallback;
			result = wsPasswordCallback.getUsage() == WSPasswordCallback.PASSWORD_ENCRYPTOR_PASSWORD
					|| wsPasswordCallback.getUsage() == WSPasswordCallback.SIGNATURE;
		}
		return result;
	}

	@Override
	public void handle(Callback pCallback) throws IOException,
			UnsupportedCallbackException {
		((WSPasswordCallback) pCallback).setPassword(keystorePassword);
	}
}
