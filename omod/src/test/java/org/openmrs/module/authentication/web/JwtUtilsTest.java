package org.openmrs.module.authentication.web;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.PrematureJwtException;
import io.jsonwebtoken.impl.DefaultClaims;
import io.jsonwebtoken.lang.DateFormats;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.time.DateUtils;
import org.hamcrest.Matchers;
import org.jose4j.jwk.JsonWebKeySet;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.openmrs.api.APIException;
import org.openmrs.module.authentication.web.controller.CustomLogoutSuccessHandlerTest;
import org.openmrs.util.OpenmrsUtil;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.reflect.Whitebox;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Date;
import java.util.Properties;

import static io.jsonwebtoken.SignatureAlgorithm.RS256;
import static org.junit.Assert.assertEquals;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.*;
import static org.openmrs.module.authentication.web.JwtUtils.*;
import static org.powermock.api.mockito.PowerMockito.mockStatic;

@RunWith(PowerMockRunner.class)
@PowerMockIgnore("javax.management.*")
@PrepareForTest({ OpenmrsUtil.class, FileUtils.class, Utils.class, HttpUtils.class })
public class JwtUtilsTest {
	
	@Mock
	private Properties mockProps;
	
	@Mock
	private File mockKeyFile;
	
	@Rule
	public ExpectedException ee = ExpectedException.none();
	
	@Before
	public void setup() {
		MockitoAnnotations.initMocks(this);
		mockStatic(OpenmrsUtil.class);
		mockStatic(Utils.class);
		mockStatic(FileUtils.class);
		mockStatic(HttpUtils.class);
		Whitebox.setInternalState(JwtUtils.class, PublicKey.class, (Object) null);
		Whitebox.setInternalState(JwtUtils.class, JsonWebKeySet.class, (Object) null);
		Whitebox.setInternalState(JwtUtils.class, "keysInitialized", false);
	}
	
	@Test
	public void getPublicKey_shouldLookUpTheKeyFromAnOauthProperty() throws Exception {
		final String key = IOUtils.toString(getClass().getClassLoader().getResourceAsStream("publicKey.txt"), "UTF-8");
		PublicKey expectedKey = JwtUtils.stringToPublicKey(key.trim());
		when(mockProps.getProperty(OAUTH_PROP_KEY)).thenReturn(key);
		
		assertEquals(expectedKey, JwtUtils.getPublicKey(null, mockProps));
	}
	
	@Test
	public void getPublicKey_shouldLookUpTheKeyFromAFile() throws Exception {
		final String key = IOUtils.toString(getClass().getClassLoader().getResourceAsStream("publicKey.txt"), "UTF-8");
		final String testFile = "test.txt";
		when(mockProps.getProperty(OAUTH_PROP_KEY_FILE)).thenReturn(testFile);
		when(Utils.getFileInAppDataDirectory(testFile)).thenReturn(mockKeyFile);
		when(mockKeyFile.exists()).thenReturn(true);
		when(FileUtils.readFileToString(mockKeyFile, StandardCharsets.UTF_8)).thenReturn(key);
		PublicKey expectedKey = JwtUtils.stringToPublicKey(key.trim());
		
		assertEquals(expectedKey, JwtUtils.getPublicKey(null, mockProps));
	}
	
	@Test
	public  void getPublicKey_shouldNotLookUpTheKeyFromTheIdentityProviderIfNoUrlIsSet() throws Exception {
		Assert.assertNull(JwtUtils.getPublicKey(null, mockProps));
		PowerMockito.verifyStatic(null,never());
		HttpUtils.getJsonWebKeys(anyString());
	}
	
	@Test
	public void getPublicKey_shouldLookUpTheKeyFromTheIdentityProviderIfUrlIsSet() throws Exception {
		final String url = "http://someurl.com";
		when(mockProps.getProperty(OAUTH_PROP_KEYS_URL)).thenReturn(url);
		final String keysJson = IOUtils.toString(getClass().getClassLoader().getResourceAsStream("keys.json"), "UTF-8");
		JsonWebKeySet jsonWebKeySet = new JsonWebKeySet(keysJson);
		when(HttpUtils.getJsonWebKeys(url)).thenReturn(keysJson);
		Key expectedKey = jsonWebKeySet.getJsonWebKeys().get(0).getKey();
		final String key = IOUtils.toString(getClass().getClassLoader().getResourceAsStream("jwtToken.txt"), "UTF-8");
		
		assertEquals(expectedKey, JwtUtils.getPublicKey(key, mockProps));
	}
	
	@Test
	public void parseAndVerifyToken_shouldFailIfNoPublicKeyIsSet() throws Exception {
		Whitebox.setInternalState(JwtUtils.class, "keysInitialized", true);
		ee.expect(APIException.class);
		ee.expectMessage(Matchers.equalTo("Unable to find public key to verify JWT token signatures"));
		
		JwtUtils.parseAndVerifyToken("someToken", mockProps);
	}
	
	@Test
	public void parseAndVerifyToken_shouldParseAndVerifyAValidToken() throws Exception {
		KeyPair keyPair = Keys.keyPairFor(RS256);
		final String subject = "tester";
		Claims expected = new DefaultClaims();
		expected.setSubject(subject);
		Date dateIssued = new Date();
		Date expiryDate = DateUtils.addMinutes(dateIssued, 2);
		expected.setIssuedAt(dateIssued);
		expected.setExpiration(expiryDate);
		String jwtToken = Jwts.builder().signWith(keyPair.getPrivate(), RS256).setClaims(expected).compact();
		Whitebox.setInternalState(JwtUtils.class, "keysInitialized", true);
		Whitebox.setInternalState(JwtUtils.class, PublicKey.class, keyPair.getPublic());
		Whitebox.setInternalState(JwtUtils.class, "keysInitialized", true);
		
		Claims actual = JwtUtils.parseAndVerifyToken(jwtToken, null);
		
		assertEquals(expected.size(), actual.size());
		assertEquals(expected.getSubject(), actual.getSubject());
		assertEquals(expected.getIssuedAt(), actual.getIssuedAt());
		assertEquals(expected.getExpiration(), actual.getExpiration());
	}
	
	@Test
	public void parseAndVerifyToken_shouldFailForATokenIfExpiryDateHasPassed() throws Exception {
		KeyPair keyPair = Keys.keyPairFor(RS256);
		final String subject = "tester";
		Claims expected = new DefaultClaims();
		expected.setSubject(subject);
		Date expiryDate = DateUtils.addSeconds(new Date(), -1);
		expected.setIssuedAt(DateUtils.addMinutes(expiryDate, -2));
		expected.setExpiration(expiryDate);
		String jwtToken = Jwts.builder().signWith(keyPair.getPrivate(), RS256).setClaims(expected).compact();
		Whitebox.setInternalState(JwtUtils.class, "keysInitialized", true);
		Whitebox.setInternalState(JwtUtils.class, PublicKey.class, keyPair.getPublic());
		Whitebox.setInternalState(JwtUtils.class, "keysInitialized", true);
		ee.expect(ExpiredJwtException.class);
		ee.expectMessage("JWT expired at " + DateFormats.formatIso8601(expiryDate, false));
		
		JwtUtils.parseAndVerifyToken(jwtToken, null);
	}
	
	@Test
	public void parseAndVerifyToken_shouldFailForAnInValidToken() throws Exception {
		KeyPair keyPair = Keys.keyPairFor(RS256);
		Claims expected = new DefaultClaims();
		expected.setSubject("tester");
		String jwtToken = Jwts.builder().signWith(keyPair.getPrivate(), RS256).setClaims(expected).compact();
		Whitebox.setInternalState(JwtUtils.class, "keysInitialized", true);
		Whitebox.setInternalState(JwtUtils.class, PublicKey.class, Keys.keyPairFor(RS256).getPublic());
		ee.expect(SignatureException.class);
		ee.expectMessage("JWT signature does not match locally computed signature. JWT validity cannot be asserted and should not be trusted.");
		
		JwtUtils.parseAndVerifyToken(jwtToken, null);
	}
	
	@Test
	public void parseAndVerifyToken_shouldFailForATokenWithAFutureNotBeforeDate() throws Exception {
		KeyPair keyPair = Keys.keyPairFor(RS256);
		final String subject = "tester";
		Claims expected = new DefaultClaims();
		expected.setSubject(subject);
		Date dateIssued = new Date();
		expected.setIssuedAt(dateIssued);
		Date notBeforeDate = DateUtils.addMinutes(dateIssued, 2);
		expected.setNotBefore(notBeforeDate);
		expected.setExpiration(DateUtils.addMinutes(dateIssued, 3));
		String jwtToken = Jwts.builder().signWith(keyPair.getPrivate(), RS256).setClaims(expected).compact();
		Whitebox.setInternalState(JwtUtils.class, "keysInitialized", true);
		Whitebox.setInternalState(JwtUtils.class, PublicKey.class, keyPair.getPublic());
		Whitebox.setInternalState(JwtUtils.class, "keysInitialized", true);
		ee.expect(PrematureJwtException.class);
		ee.expectMessage("JWT must not be accepted before " + DateFormats.formatIso8601(notBeforeDate, false));
		
		JwtUtils.parseAndVerifyToken(jwtToken, null);
	}
	
}
