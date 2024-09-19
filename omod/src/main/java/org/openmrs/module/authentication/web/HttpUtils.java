package org.openmrs.module.authentication.web;

import org.apache.commons.io.IOUtils;
import org.openmrs.api.APIException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

/**
 * Contains http utility methods
 */
public class HttpUtils {
	
	protected static final Logger log = LoggerFactory.getLogger(HttpUtils.class);
	
	/**
	 * Fetches JSON web keys from the Identity provider at the specified URL
	 * 
	 * @param url the URL of the identity provider
	 * @return JSON web keys
	 * @throws Exception
	 */
	public static String getJsonWebKeys(String url) throws Exception {
		HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
		
		try {
			connection.setRequestProperty("Accept", "application/json");
			connection.setDoInput(true);
			connection.setUseCaches(false);
			
			if (log.isDebugEnabled()) {
				log.debug("Fetching JSON web keys from identity provider");
			}
			
			connection.connect();
			
			if (connection.getResponseCode() != 200) {
				final String error = connection.getResponseCode() + " " + connection.getResponseMessage();
				throw new APIException("Unexpected response " + error + " from identity provider");
			}
			
			return IOUtils.toString(connection.getInputStream(), StandardCharsets.UTF_8);
		}
		finally {
			if (connection != null) {
				connection.disconnect();
			}
		}
	}
	
}
