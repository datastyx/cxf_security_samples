package demo.wssec.service.common;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Handle the different WSPasswordCallbacks
 */
public class WSPasswordCallbackHandler implements CallbackHandler {

	/**
	 * List of the different subcallback handlers which are able to handle
	 * WSPasswordCallbacks type.
	 */
	private List<ISubCallbackHandler> subCallbackHandlers = new ArrayList<ISubCallbackHandler>();

	/**
	 * Logger of the class.
	 */
	private static final Logger LOGGER = LoggerFactory
			.getLogger(WSPasswordCallbackHandler.class.getName());

	@Override
	public void handle(Callback[] callbacks) throws IOException,
			UnsupportedCallbackException {
		for (Callback callback : callbacks) {
			if (callback instanceof WSPasswordCallback) {
				boolean handled = false;
				// find a sub callback handler that can handle the callback.
				for (ISubCallbackHandler subCallbackHandler : subCallbackHandlers) {
					if (subCallbackHandler.canHandle(callback)) {
						handled = true;
						subCallbackHandler.handle(callback);
						break;
					}
				}
				if (!handled) {
					LOGGER.warn(((WSPasswordCallback) callback).getUsage()
							+ " not handled");
				}
			}
		}
	}

	/**
	 * @return get the subcallback handlers.
	 */
	public List<ISubCallbackHandler> getSubCallbackHandlers() {
		return subCallbackHandlers;
	}

	/**
	 * @param subCallbackHandlers
	 *            list of all the callbackhandlers to use.
	 */
	public void setSubCallbackHandlers(
			List<ISubCallbackHandler> subCallbackHandlers) {
		this.subCallbackHandlers = subCallbackHandlers;
	}
}
