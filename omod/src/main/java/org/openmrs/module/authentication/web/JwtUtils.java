package org.openmrs.module.authentication.web;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.SignatureException;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.VerificationJwkSelector;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.openmrs.api.APIException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Properties;

import static org.jose4j.jwa.AlgorithmConstraints.ConstraintType.PERMIT;

/**
 * Provides utility methods for parsing and verifying JWT tokens
 */
public class JwtUtils {
	
	protected static final Logger log = LoggerFactory.getLogger(JwtUtils.class);
	
	public static final String OAUTH_PROP_KEY = "publicKey";
	
	public static final String OAUTH_PROP_KEY_FILE = "publicKeyFilename";
	
	public static final String OAUTH_PROP_KEYS_URL = "keysUrl";
	
	public static PublicKey localPublicKey = null;
	
	public static boolean keysInitialized = false;
	
	public static JsonWebKeySet remoteJsonWebKeySet = null;
	
	public static final String[] SUPPORTED_ALGORITHMS = new String[] { AlgorithmIdentifiers.RSA_USING_SHA256,
	        AlgorithmIdentifiers.RSA_USING_SHA384, AlgorithmIdentifiers.RSA_USING_SHA512,
	        AlgorithmIdentifiers.RSA_PSS_USING_SHA256, AlgorithmIdentifiers.RSA_PSS_USING_SHA384,
	        AlgorithmIdentifiers.RSA_PSS_USING_SHA512 };
	
	/**
	 * Parses and verifies a JWT token
	 * 
	 * @param jwtToken the JWT token
	 * @param oauthProps oauth2 properties instance
	 * @return Claims object
	 * @throws Exception
	 */
	public static Claims parseAndVerifyToken(String jwtToken, Properties oauthProps) throws Exception {
		PublicKey effectiveKey = getPublicKey(jwtToken, oauthProps);
		if (effectiveKey == null) {
			throw new APIException("Unable to find public key to verify JWT token signatures");
		}
		
		return Jwts.parserBuilder().setSigningKey(effectiveKey).build().parseClaimsJws(jwtToken).getBody();
	}
	
	/**
	 * Gets the public key based on the specified oauthProps properties. Lookup order is the oauth
	 * property, and then the configured file containing the key.
	 * 
	 * @param jwt the JWT token that will verified with the public key
	 * @param oauthProps Properties instance
	 * @return the public key
	 * @throws Exception
	 */
	public synchronized static PublicKey getPublicKey(String jwt, Properties oauthProps) throws Exception {
		if (!keysInitialized) {
			String publicKeyTxt = null;
			if (StringUtils.isNotBlank(oauthProps.getProperty(OAUTH_PROP_KEY))) {
				log.info("Using public key specified via the oauth property named: " + OAUTH_PROP_KEY);
				
				publicKeyTxt = oauthProps.getProperty(OAUTH_PROP_KEY).trim();
			}
			
			if (StringUtils.isBlank(publicKeyTxt) && StringUtils.isNotBlank(oauthProps.getProperty(OAUTH_PROP_KEY_FILE))) {
				File file = Utils.getFileInAppDataDirectory(oauthProps.getProperty(OAUTH_PROP_KEY_FILE).trim());
				if (file.exists()) {
					log.info("Using public key from the file: " + file);
					
					publicKeyTxt = FileUtils.readFileToString(file, StandardCharsets.UTF_8).trim();
				} else {
					log.error("The oauth public key file doesn't exist -> " + file.getAbsolutePath());
				}
			}
			
			if (StringUtils.isNotBlank(publicKeyTxt)) {
				localPublicKey = stringToPublicKey(publicKeyTxt);
			}
			
			if (localPublicKey == null && StringUtils.isNotBlank(oauthProps.getProperty(OAUTH_PROP_KEYS_URL))) {
				String keys = HttpUtils.getJsonWebKeys(oauthProps.getProperty(OAUTH_PROP_KEYS_URL).trim());
				remoteJsonWebKeySet = new JsonWebKeySet(keys);
			}
			
			keysInitialized = true;
		}
		
		if (localPublicKey != null) {
			return localPublicKey;
		}
		
		if (remoteJsonWebKeySet != null) {
			//Select the correct key from the key set based on the details in the JWT token and extract out the public key
			JsonWebSignature jws = new JsonWebSignature();
			jws.setAlgorithmConstraints(new AlgorithmConstraints(PERMIT, SUPPORTED_ALGORITHMS));
			jws.setCompactSerialization(jwt);
			VerificationJwkSelector keySelector = new VerificationJwkSelector();
			JsonWebKey jwk = keySelector.select(jws, remoteJsonWebKeySet.getJsonWebKeys());
			if (jwk != null) {
				jws.setKey(jwk.getKey());
				//Do a quick check of the signature, an exception will be thrown in case of an unsupported algorithm
				if (!jws.verifySignature()) {
					throw new SignatureException("JWT signature does not match locally computed signature");
				}
				
				return (PublicKey) jwk.getKey();
			} else {
				log.warn("Found no matching key to verify JWT tokens");
			}
		}
		
		return null;
	}
	
	/**
	 * Parses a base64 encoded string and creates a PublicKey object
	 * 
	 * @param publicKeyTxt public key String
	 * @return PublicKey object
	 * @throws Exception
	 */
	public static PublicKey stringToPublicKey(String publicKeyTxt) throws Exception {
		//TODO Support other key types other than RSA depending on the alg value in the token header
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyTxt));
		return keyFactory.generatePublic(keySpec);
	}
	
}
