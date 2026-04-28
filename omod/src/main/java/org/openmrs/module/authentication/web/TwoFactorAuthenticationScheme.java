/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 * <p>
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.authentication.web;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.openmrs.User;
import org.openmrs.api.context.Authenticated;
import org.openmrs.api.context.AuthenticationScheme;
import org.openmrs.api.context.BasicAuthenticated;
import org.openmrs.api.context.Context;
import org.openmrs.api.context.ContextAuthenticationException;
import org.openmrs.api.context.Credentials;
import org.openmrs.api.context.Daemon;
import org.openmrs.module.DaemonToken;
import org.openmrs.module.authentication.AuthenticationConfig;
import org.openmrs.module.authentication.AuthenticationCredentials;
import org.openmrs.module.authentication.AuthenticationUtil;
import org.openmrs.module.authentication.ConfigurableAuthenticationScheme;
import org.openmrs.module.authentication.UserLogin;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

/**
 * An authentication scheme that supports a primary and secondary authentication factor
 */
public class TwoFactorAuthenticationScheme extends WebAuthenticationScheme {

	protected final Log log = LogFactory.getLog(getClass());

	// Daemon Token
	private static DaemonToken daemonToken;

	// User configuration
	public static final String USER_PROPERTY_SECONDARY_TYPE = "authentication.secondaryType";

	// Remember-me configuration keys
	public static final String REMEMBER_ME_ENABLED = "rememberMeEnabled";
	public static final String REMEMBER_ME_PARAM = "rememberMeParam";
	public static final String REMEMBER_ME_COOKIE_NAME = "rememberMeCookieName";
	public static final String REMEMBER_ME_DURATION_MINUTES = "rememberMeDurationMinutes";
	public static final int REMEMBER_ME_DURATION_MINUTES_DEFAULT = 30 * 24 * 60;  // 30 days by default
	public static final String REMEMBER_ME_COOKIE_PATH = "rememberMeCookiePath";
	public static final String REMEMBER_ME_COOKIE_SECURE = "rememberMeCookieSecure";

	protected List<String> primaryOptions = new ArrayList<>();
	protected List<String> secondaryOptions = new ArrayList<>();
	protected boolean rememberMeEnabled = false;
	protected String rememberMeParam = "rememberMe";
	protected String rememberMeCookieName = null;
	protected int rememberMeDurationMinutes = REMEMBER_ME_DURATION_MINUTES_DEFAULT;
	protected String rememberMeCookiePath = "/";
	protected boolean rememberMeCookieSecure = true;

	/**
	 * This supports configuring the `primaryOptions` and `secondaryOptions` that are supported factors
	 * These are both expected to be comma-delimited lists of schemeIds
	 * @see ConfigurableAuthenticationScheme#configure(String, Properties)
	 */
	@Override
	public void configure(String schemeId, Properties config) {
		super.configure(schemeId, config);
		primaryOptions = AuthenticationUtil.getStringList(config.getProperty("primaryOptions"), ",");
		secondaryOptions = AuthenticationUtil.getStringList(config.getProperty("secondaryOptions"), ",");
		rememberMeEnabled = AuthenticationUtil.getBoolean(config.getProperty(REMEMBER_ME_ENABLED), false);
		rememberMeParam = config.getProperty(REMEMBER_ME_PARAM, "rememberMe");
		rememberMeCookieName = config.getProperty(REMEMBER_ME_COOKIE_NAME, "authentication." + schemeId + ".rememberMe");
		rememberMeDurationMinutes = AuthenticationUtil.getInteger(config.getProperty(REMEMBER_ME_DURATION_MINUTES), REMEMBER_ME_DURATION_MINUTES_DEFAULT);
		rememberMeCookiePath = config.getProperty(REMEMBER_ME_COOKIE_PATH, "/");
		rememberMeCookieSecure = AuthenticationUtil.getBoolean(config.getProperty(REMEMBER_ME_COOKIE_SECURE), true);
	}

	public static void setDaemonToken(DaemonToken daemonToken) {
		TwoFactorAuthenticationScheme.daemonToken = daemonToken;
	}

	/**
	 * @see WebAuthenticationScheme#isUserConfigurationRequired(User)
	 */
	@Override
	public boolean isUserConfigurationRequired(User user) {
		return false;
	}

	@Override
	public String getChallengeUrl(AuthenticationSession session) {
		User candidateUser = session.getUserLogin().getUser();
		if (candidateUser == null) {
			return getPrimaryAuthenticationScheme().getChallengeUrl(session);
		}
		WebAuthenticationScheme secondaryScheme = getSecondaryAuthenticationScheme(session, candidateUser);
		if (secondaryScheme != null) {
			return secondaryScheme.getChallengeUrl(session);
		}
		return null;
	}

	/**
	 * @see WebAuthenticationScheme#getCredentials(AuthenticationSession)
	 */
	@Override
	public AuthenticationCredentials getCredentials(AuthenticationSession session) {

		UserLogin userLogin = session.getUserLogin();
		AuthenticationCredentials existingCredentials = userLogin.getUnvalidatedCredentials(getSchemeId());
		if (existingCredentials != null) {
			return existingCredentials;
		}

		// Primary Authentication
		WebAuthenticationScheme primaryScheme = getPrimaryAuthenticationScheme();
		if (!userLogin.isCredentialValidated(primaryScheme.getSchemeId())) {
			AuthenticationCredentials primaryCredentials = primaryScheme.getCredentials(session);
			if (primaryCredentials != null) {
				try {
					session.authenticate(primaryScheme, primaryCredentials);
					session.refreshDefaultLocale();
				} catch (Exception e) {
					log.trace("Primary Authentication Failed: " + primaryCredentials.getClientName(), e);
				}
			}
		}

		// Secondary Authentication
		if (userLogin.getUser() != null) {
			WebAuthenticationScheme secondaryScheme = getSecondaryAuthenticationScheme(session, userLogin.getUser());
			if (secondaryScheme != null) {
				if (!userLogin.isCredentialValidated(secondaryScheme.getSchemeId())) {
					// Try to bypass secondary authentication via a valid remember-me cookie.
					// On success, the original expiry is stashed on the session so that the rotated cookie issued
					// in afterAuthenticationSuccess inherits it, rather than effectively never expiring.
					Long preservedExpiry = validateRememberMeBypass(session, userLogin.getUser(), secondaryScheme);
					if (preservedExpiry != null) {
						userLogin.authenticationSuccessful(secondaryScheme.getSchemeId(),
								new BasicAuthenticated(userLogin.getUser(), secondaryScheme.getSchemeId()));
						session.setHttpSessionAttribute(getSessionKeyForRememberMeBypass(), preservedExpiry);
					}
					else {
						AuthenticationCredentials secondaryCredentials = secondaryScheme.getCredentials(session);
						if (secondaryCredentials != null) {
							try {
								session.authenticate(secondaryScheme, secondaryCredentials).getUser();
							} catch (Exception e) {
								log.trace("Secondary Authentication Failed: " + secondaryCredentials.getClientName(), e);
							}
						}
					}
				}
			}
			if (secondaryScheme == null || userLogin.isCredentialValidated(secondaryScheme.getSchemeId())) {
				TwoFactorAuthenticationCredentials credentials = new TwoFactorAuthenticationCredentials(
						userLogin.getUser(), userLogin.getValidatedCredentials()
				);
				userLogin.addUnvalidatedCredentials(credentials);
				return credentials;
			}

		}
		return null;
	}

	/**
	 * Issues a remember-me cookie if either the user requested it on this login, or a remember-me cookie was used
	 * to bypass secondary authentication during this session (in which case the token is rotated).  Issuance is
	 * skipped when remember-me is disabled, when there is no authenticated user, or when the user has no secondary
	 * authentication factor configured (in which case the cookie has no effect).
	 * @see WebAuthenticationScheme#afterAuthenticationSuccess(AuthenticationSession)
	 */
	@Override
	public void afterAuthenticationSuccess(AuthenticationSession session) {
		super.afterAuthenticationSuccess(session);
		if (!rememberMeEnabled) {
			return;
		}
		User user = session.getUserLogin().getUser();
		if (user == null || getSecondaryAuthenticationSchemeIdsForUser(user).isEmpty()) {
			return;
		}
		// If the bypass was used this session, preserve the original expiry so periodic logins via cookie can't
		// effectively extend remember-me indefinitely - the user must re-validate the secondary factor before the
		// expiry to refresh the lifetime.  If the user is opting in fresh (rememberMe param), use a new expiry.
		Object bypassAttr = session.getHttpSession().getAttribute(getSessionKeyForRememberMeBypass());
		Long preservedExpiry = (bypassAttr instanceof Long) ? (Long) bypassAttr : null;
		boolean requested = AuthenticationUtil.getBoolean(session.getRequestParam(rememberMeParam), false);
		if (preservedExpiry != null || requested) {
			rotateAndIssueRememberMeCookie(session, user, preservedExpiry);
		}
	}

	/**
	 * @see AuthenticationScheme#authenticate(Credentials)
	 */
	@Override
	public Authenticated authenticate(AuthenticationCredentials credentials, UserLogin userLogin) {
		// Ensure the credentials provided are of the expected type
		if (!(credentials instanceof TwoFactorAuthenticationCredentials)) {
			throw new ContextAuthenticationException("authentication.error.incorrectCredentialsForScheme");
		}
		TwoFactorAuthenticationCredentials mfaCreds = (TwoFactorAuthenticationCredentials) credentials;
		if (userLogin.getUser() != null && !userLogin.getUser().equals(mfaCreds.user)) {
			throw new ContextAuthenticationException("authentication.error.userDiffersFromCandidateUser");
		}
		if (!mfaCreds.validatedCredentials.contains(getPrimaryAuthenticationScheme().getSchemeId())) {
			throw new ContextAuthenticationException("authentication.error.primaryAuthenticationRequired");
		}
		List<String> secondarySchemes = getSecondaryAuthenticationSchemeIdsForUser(mfaCreds.user);
		if (!secondarySchemes.isEmpty()) {
			int numSecondarySchemesValidated = 0;
			for (String secondarySchemeId : secondarySchemes) {
				if (mfaCreds.validatedCredentials.contains(secondarySchemeId)) {
					numSecondarySchemesValidated++;
				}
			}
			if (numSecondarySchemesValidated == 0) {
				throw new ContextAuthenticationException("authentication.error.secondaryAuthenticationRequired");
			}
		}
		return new BasicAuthenticated(mfaCreds.user, credentials.getAuthenticationScheme());
	}

	/**
	 * This returns the WebAuthenticationScheme that is configured as the primary authentication scheme,
	 * defined as the first configured authentication scheme in the `primaryOptions` configuration property
	 * If no AuthenticationScheme can be returned, or if it is not a WebAuthenticationScheme, an exception is thrown
	 * @return the WebAuthenticationScheme to use for the given MultiFactorAuthenticationCredentials
	 */
	protected WebAuthenticationScheme getPrimaryAuthenticationScheme() {
		String authScheme = null;
		if (!primaryOptions.isEmpty()) {
			authScheme = primaryOptions.get(0);
		}
		if (authScheme == null) {
			throw new ContextAuthenticationException("authentication.error.primarySchemeNotConfigured");
		}
		try {
			AuthenticationScheme scheme = AuthenticationConfig.getAuthenticationScheme(authScheme);
			if (scheme instanceof WebAuthenticationScheme) {
				return (WebAuthenticationScheme) scheme;
			}
			else {
				throw new ContextAuthenticationException("authentication.error.primarySchemeInvalidType");
			}
		}
		catch (Exception e) {
			throw new ContextAuthenticationException("authentication.error.primarySchemeInvalidConfiguration", e);
		}
	}

	/**
	 * @return the session attribute key used to store the preferred second factor scheme for the current session
	 */
	protected String getSessionKeyForSecondarySchemeId() {
		return "authentication." + getSchemeId() + ".secondarySchemeId";
	}

	public void setSecondaryAuthenticationSchemeForSession(AuthenticationSession session, String secondarySchemeId) {
		List<String> allowed = getSecondaryAuthenticationSchemeIdsForUser(session.getUserLogin().getUser());
		if (!allowed.contains(secondarySchemeId)) {
			throw new ContextAuthenticationException("authentication.error.secondFactorNotEnabledForUser");
		}
		session.getHttpSession().setAttribute(getSessionKeyForSecondarySchemeId(), secondarySchemeId);
	}

	/**
	 * This returns the WebAuthenticationScheme that is configured for the given User
	 * This is configured via a user property named `authentication.secondaryType`
	 * This throws an Exception the configured AuthenticationScheme is not a WebAuthenticationScheme
	 * @param user the User to check for configured secondary WebAuthenticationScheme
	 * @return the WebAuthenticationScheme to use for the given MultiFactorAuthenticationCredentials
	 */
	public WebAuthenticationScheme getSecondaryAuthenticationScheme(AuthenticationSession session, User user) {
		if (user != null) {
			String preferredScheme = null;
			Object sessionVal = session.getHttpSessionAttributes().get(getSessionKeyForSecondarySchemeId());
			if (sessionVal != null) {
				preferredScheme = (String) sessionVal;
			}
			else {
				List<String> secondarySchemeIds = getSecondaryAuthenticationSchemeIdsForUser(user);
				if (!secondarySchemeIds.isEmpty()) {
					preferredScheme = secondarySchemeIds.get(0);
				}
			}
			if (preferredScheme != null) {
				AuthenticationScheme scheme = AuthenticationConfig.getAuthenticationScheme(preferredScheme);
				if (scheme instanceof WebAuthenticationScheme) {
					return (WebAuthenticationScheme) scheme;
				} else {
					throw new ContextAuthenticationException("authentication.error.secondarySchemeInvalidType");
				}
			}
		}
		return null;
	}

	public List<String> getSecondaryAuthenticationSchemeIdsForUser(User user) {
		List<String> schemeIds = new ArrayList<>();
		String userProperty = user.getUserProperty(USER_PROPERTY_SECONDARY_TYPE);
		if (StringUtils.isNotBlank(userProperty)) {
			schemeIds.addAll(Arrays.asList(userProperty.split(",")));
		}
		return schemeIds;
	}

	public void addSecondaryAuthenticationSchemeForUser(User user, String schemeId) {
		List<String> schemeIds = getSecondaryAuthenticationSchemeIdsForUser(user);
		if (!schemeIds.contains(schemeId)) {
			schemeIds.add(schemeId);
			user.setUserProperty(USER_PROPERTY_SECONDARY_TYPE, String.join(",", schemeIds));
		}
	}

	public void setSecondaryAuthenticationSchemeIdsForUser(User user, List<String> schemeIds) {
		user.setUserProperty(USER_PROPERTY_SECONDARY_TYPE, String.join(",", schemeIds));
	}

	/**
	 * @return the primary authentication scheme options configured
	 */
	public List<String> getPrimaryOptions() {
		return primaryOptions;
	}

	/**
	 * @return the secondary authentication scheme options configured
	 */
	public List<String> getSecondaryOptions() {
		return secondaryOptions;
	}

	// ------------------------------------------------------------------------
	// Remember-me support
	// ------------------------------------------------------------------------

	/**
	 * @return true if remember-me is enabled via configuration
	 */
	public boolean isRememberMeEnabled() {
		return rememberMeEnabled;
	}

	/**
	 * @return the prefix used for user properties that store remember-me token series for this scheme
	 */
	protected String getRememberMeUserPropertyPrefix() {
		return "authentication." + getSchemeId() + ".rememberMe.";
	}

	/**
	 * @return the user property name where the remember-me token for the given series id is stored
	 */
	protected String getRememberMeUserPropertyName(String seriesId) {
		return getRememberMeUserPropertyPrefix() + seriesId;
	}

	/**
	 * @return the http session attribute key used to track that this session was authenticated using a remember-me cookie
	 */
	protected String getSessionKeyForRememberMeBypass() {
		return "authentication." + getSchemeId() + ".rememberMeBypass";
	}

	/**
	 * Checks whether the request carries a valid remember-me cookie for the given user that authorizes bypassing
	 * the given secondary authentication scheme.  This both validates the cookie's series/token pair against the
	 * server-side hash stored on the user and removes the consumed entry so that it cannot be replayed - a fresh
	 * cookie is issued in {@link #afterAuthenticationSuccess(AuthenticationSession)}.  Expired entries encountered
	 * along the way are also pruned.
	 * @param session the current authentication session
	 * @param user the authenticated user
	 * @param secondaryScheme the secondary authentication scheme that would otherwise be required
	 * @return the original expiry (epoch millis) of the consumed token if the cookie is valid, or null if the cookie
	 * is missing/invalid/expired and the bypass should not be granted.  The expiry is preserved so the rotated cookie
	 * keeps the same lifetime instead of resetting on every bypass.
	 */
	protected Long validateRememberMeBypass(AuthenticationSession session, User user, WebAuthenticationScheme secondaryScheme) {
		if (!rememberMeEnabled || user == null || secondaryScheme == null) {
			return null;
		}
		Cookie cookie = readRememberMeCookie(session);
		if (cookie == null) {
			return null;
		}
		SeriesAndToken parts = parseRememberMeCookieValue(cookie.getValue());
		if (parts == null) {
			expireRememberMeCookie(session);
			return null;
		}
		String stored = readRememberMeToken(user, parts.seriesId);
		if (stored == null) {
			// Browser is sending a cookie whose server-side entry no longer exists - clear it
			expireRememberMeCookie(session);
			return null;
		}
		StoredRememberMeToken storedToken = StoredRememberMeToken.parse(stored);
		if (storedToken == null) {
			// Malformed entry, remove it and clear the browser cookie too
			removeRememberMeToken(user, parts.seriesId);
			expireRememberMeCookie(session);
			return null;
		}
		if (storedToken.expiryEpochMillis <= System.currentTimeMillis()) {
			removeRememberMeToken(user, parts.seriesId);
			expireRememberMeCookie(session);
			return null;
		}
		String submittedHash = sha256Hex(parts.rawToken);
		if (!constantTimeEquals(submittedHash, storedToken.tokenHash)) {
			// Token mismatch on a known series id is suspicious - drop this series and the browser cookie
			removeRememberMeToken(user, parts.seriesId);
			expireRememberMeCookie(session);
			return null;
		}
		// Consume the matched series; afterAuthenticationSuccess will issue a rotated replacement that inherits
		// the original expiry so periodic bypass logins do not effectively extend remember-me indefinitely.
		removeRememberMeToken(user, parts.seriesId);
		return storedToken.expiryEpochMillis;
	}

	/**
	 * Issues a fresh remember-me cookie for the given user.  Any cookie sent with the current request is also
	 * cleaned up (its server-side entry is removed) so that exactly one active series per browser is maintained.
	 * @param session the current authentication session
	 * @param user the authenticated user
	 * @param preservedExpiry if non-null, the new token will inherit this expiry (epoch millis) instead of
	 * starting a fresh {@code rememberMeDurationMinutes} window. Used during cookie rotation after a bypass so the
	 * lifetime is anchored to the user's last successful secondary-factor authentication, not to the most recent
	 * bypass login.
	 */
	protected void rotateAndIssueRememberMeCookie(AuthenticationSession session, User user, Long preservedExpiry) {
		// Drop any pre-existing token entry for the cookie this request arrived with
		Cookie existing = readRememberMeCookie(session);
		if (existing != null) {
			SeriesAndToken parts = parseRememberMeCookieValue(existing.getValue());
			if (parts != null) {
				removeRememberMeToken(user, parts.seriesId);
			}
		}
		long now = System.currentTimeMillis();
		long expiry = (preservedExpiry != null && preservedExpiry > now)
				? preservedExpiry
				: now + (rememberMeDurationMinutes * 60_000L);
		int maxAgeSeconds = (int) Math.max(0L, (expiry - now) / 1000L);
		String seriesId = generateRandomToken();
		String rawToken = generateRandomToken();
		String stored = sha256Hex(rawToken) + ":" + expiry;
		writeRememberMeToken(user, seriesId, stored);
		writeRememberMeCookie(session, seriesId + "." + rawToken, maxAgeSeconds);
	}

	/**
	 * @return the remember-me cookie sent with the current request, or null if none is present or readable
	 */
	protected Cookie readRememberMeCookie(AuthenticationSession session) {
		HttpServletRequest request = session.getHttpRequest();
		if (request == null || rememberMeCookieName == null) {
			return null;
		}
		Cookie[] cookies = request.getCookies();
		if (cookies == null) {
			return null;
		}
		for (Cookie cookie : cookies) {
			if (rememberMeCookieName.equals(cookie.getName())) {
				return cookie;
			}
		}
		return null;
	}

	/**
	 * Adds a remember-me cookie to the response with the configured attributes.  HttpOnly is set reflectively so
	 * the code compiles against the legacy Servlet API 2.3 jar that some transitive dependencies pull onto the
	 * classpath; on any Servlet 3.0+ container actually serving production traffic, the HttpOnly attribute is
	 * applied.
	 */
	protected void writeRememberMeCookie(AuthenticationSession session, String value, int maxAgeSeconds) {
		HttpServletResponse response = session.getHttpResponse();
		if (response == null) {
			return;
		}
		Cookie cookie = new Cookie(rememberMeCookieName, value);
		if (StringUtils.isNotBlank(rememberMeCookiePath)) {
			cookie.setPath(rememberMeCookiePath);
		}
		cookie.setMaxAge(maxAgeSeconds);
		cookie.setSecure(rememberMeCookieSecure);
		invokeSetHttpOnly(cookie);
		response.addCookie(cookie);
	}

	/**
	 * Sends a Set-Cookie header that expires the remember-me cookie immediately, so the browser stops sending it.
	 * Used when we encounter and reject a cookie (expired entry, tampered token, unknown series) so the browser
	 * state matches the server state.
	 */
	protected void expireRememberMeCookie(AuthenticationSession session) {
		HttpServletResponse response = session.getHttpResponse();
		if (response == null) {
			return;
		}
		Cookie cookie = new Cookie(rememberMeCookieName, "");
		if (StringUtils.isNotBlank(rememberMeCookiePath)) {
			cookie.setPath(rememberMeCookiePath);
		}
		cookie.setMaxAge(0);
		cookie.setSecure(rememberMeCookieSecure);
		invokeSetHttpOnly(cookie);
		response.addCookie(cookie);
	}

	/**
	 * Calls {@code Cookie#setHttpOnly(true)} via reflection. Servlet 3.0+ (production containers) supports it; the
	 * stale 2.3 servlet-api on the test classpath does not. Failing silently here lets tests run while production
	 * still gets the HttpOnly attribute.
	 */
	private static void invokeSetHttpOnly(Cookie cookie) {
		try {
			Method m = Cookie.class.getMethod("setHttpOnly", boolean.class);
			m.invoke(cookie, true);
		}
		catch (Throwable ignored) {
			// Older Servlet API; HttpOnly attribute will be omitted
		}
	}

	/**
	 * Parses the raw cookie value into a series id and raw token.  Returns null if the value does not match the
	 * expected format.
	 */
	protected SeriesAndToken parseRememberMeCookieValue(String value) {
		if (StringUtils.isBlank(value)) {
			return null;
		}
		int sep = value.indexOf('.');
		if (sep <= 0 || sep == value.length() - 1) {
			return null;
		}
		return new SeriesAndToken(value.substring(0, sep), value.substring(sep + 1));
	}

	/**
	 * @return the stored remember-me entry value for the given user and series id, or null if not set
	 */
	protected String readRememberMeToken(User user, String seriesId) {
		return user.getUserProperty(getRememberMeUserPropertyName(seriesId));
	}

	/**
	 * Persists the remember-me entry value for the given user and series id.
	 * This is run in a Daemon thread so it can be invoked during the unauthenticated phase of the login workflow.
	 */
	protected void writeRememberMeToken(User user, String seriesId, String value) {
		String propertyName = getRememberMeUserPropertyName(seriesId);
		Daemon.runInDaemonThreadAndWait(() -> {
            User userToUpdate = Context.getUserService().getUser(user.getUserId());
            Context.getUserService().setUserProperty(userToUpdate, propertyName, value);
        }, daemonToken);
	}

	/**
	 * Removes the remember-me entry for the given user and series id.
	 * This is run in a Daemon thread so it can be invoked during the unauthenticated phase of the login workflow.
	 */
	protected void removeRememberMeToken(User user, String seriesId) {
		String propertyName = getRememberMeUserPropertyName(seriesId);
		Daemon.runInDaemonThreadAndWait(() -> {
			User userToUpdate = Context.getUserService().getUser(user.getUserId());
			Context.getUserService().removeUserProperty(userToUpdate, propertyName);
		}, daemonToken);
	}

	/**
	 * Removes all remember-me entries for the given user, including any expired or unrelated series.  Useful for
	 * "log out of all devices" workflows.
	 * @param user the user to clear tokens for
	 */
	public void clearAllRememberMeTokens(User user) {
		if (user == null) {
			return;
		}
		String prefix = getRememberMeUserPropertyPrefix();
		List<String> toRemove = new ArrayList<>();
		Map<String, String> userProperties = user.getUserProperties();
		if (userProperties != null) {
			for (String key : userProperties.keySet()) {
				if (key != null && key.startsWith(prefix)) {
					toRemove.add(key.substring(prefix.length()));
				}
			}
		}
		for (String seriesId : toRemove) {
			removeRememberMeToken(user, seriesId);
		}
	}

	/**
	 * @return a URL-safe base64 encoding of 32 random bytes from a SecureRandom source
	 */
	protected String generateRandomToken() {
		byte[] bytes = new byte[32];
		new SecureRandom().nextBytes(bytes);
		return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
	}

	/**
	 * @return the SHA-256 hex digest of the given input
	 */
	protected static String sha256Hex(String input) {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
			StringBuilder sb = new StringBuilder(hash.length * 2);
			for (byte b : hash) {
				sb.append(String.format("%02x", b));
			}
			return sb.toString();
		}
		catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("SHA-256 not available", e);
		}
	}

	/**
	 * Constant-time string comparison to avoid timing-based attacks against the stored hash
	 */
	protected static boolean constantTimeEquals(String a, String b) {
		if (a == null || b == null) {
			return false;
		}
		byte[] ab = a.getBytes(StandardCharsets.UTF_8);
		byte[] bb = b.getBytes(StandardCharsets.UTF_8);
		return MessageDigest.isEqual(ab, bb);
	}

	/**
	 * Holder for the parsed pieces of a remember-me cookie value.
	 */
	protected static class SeriesAndToken {
		final String seriesId;
		final String rawToken;
		SeriesAndToken(String seriesId, String rawToken) {
			this.seriesId = seriesId;
			this.rawToken = rawToken;
		}
	}

	/**
	 * Holder for the parsed pieces of a stored remember-me token entry (`tokenHash:expiryEpochMillis`).
	 */
	protected static class StoredRememberMeToken {
		final String tokenHash;
		final long expiryEpochMillis;
		StoredRememberMeToken(String tokenHash, long expiryEpochMillis) {
			this.tokenHash = tokenHash;
			this.expiryEpochMillis = expiryEpochMillis;
		}
		static StoredRememberMeToken parse(String stored) {
			if (StringUtils.isBlank(stored)) {
				return null;
			}
			int sep = stored.lastIndexOf(':');
			if (sep <= 0 || sep == stored.length() - 1) {
				return null;
			}
			try {
				long expiry = Long.parseLong(stored.substring(sep + 1));
				return new StoredRememberMeToken(stored.substring(0, sep), expiry);
			}
			catch (NumberFormatException e) {
				return null;
			}
		}
	}

	/**
	 * Credentials inner class, to enable access and visibility of credential details to be limited to scheme
	 */
	public class TwoFactorAuthenticationCredentials implements AuthenticationCredentials {

		protected final User user;
		protected final Set<String> validatedCredentials = new HashSet<>();

		@Override
		public String getAuthenticationScheme() {
			return getSchemeId();
		}

		protected TwoFactorAuthenticationCredentials(User user, Set<String> validatedCredentials) {
			this.user = user;
			if (validatedCredentials != null) {
				this.validatedCredentials.addAll(validatedCredentials);
			}
		}

		@Override
		public String getClientName() {
			return user == null ? null : user.getUsername();
		}
	}
}
