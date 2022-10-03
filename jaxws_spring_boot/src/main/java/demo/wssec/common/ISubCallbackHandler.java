package demo.wssec.common;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;

/**
 * Define a sub callback handler in order to be called by a callbackHandler.
 */
public interface ISubCallbackHandler {

	/**
	 * 
	 * @param pCallback
	 *            the callback to check
	 * @return true if the subcallback handler is able to perform this callback.
	 */
	public boolean canHandle(Callback pCallback);

	/**
	 * @param pCallback
	 *            the callback to perform.
	 */
	public void handle(Callback pCallback) throws IOException,
			UnsupportedCallbackException;
}
