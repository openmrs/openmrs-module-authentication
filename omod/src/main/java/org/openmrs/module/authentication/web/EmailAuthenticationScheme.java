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
import org.apache.commons.validator.routines.EmailValidator;
import org.openmrs.User;
import org.openmrs.api.context.Authenticated;
import org.openmrs.api.context.BasicAuthenticated;
import org.openmrs.api.context.Context;
import org.openmrs.api.context.ContextAuthenticationException;
import org.openmrs.messagesource.MessageSourceService;
import org.openmrs.module.authentication.AuthenticationCredentials;
import org.openmrs.module.authentication.AuthenticationUtil;
import org.openmrs.module.authentication.UserLogin;
import org.openmrs.notification.Message;
import org.openmrs.notification.MessageException;
import org.openmrs.util.PrivilegeConstants;
import org.springframework.context.MessageSource;

import java.security.SecureRandom;
import java.util.Properties;

/**
 * This is an implementation of a WebAuthenticationScheme that is intended to be used as a secondary authentication
 * scheme and validates a one-time code sent to the user's email address.
 * This scheme supports configuration parameters that enable implementations to use it with their own pages.
 * This includes the ability to configure the `loginPage` that the user should be taken to, as well as the
 * `codeParam` that should be read from the http request submission to authenticate.
 */
public class EmailAuthenticationScheme extends WebAuthenticationScheme {

	public static final String LOGIN_PAGE = "loginPage";
	public static final String CODE_PARAM = "codeParam";
	public static final String CODE_LENGTH = "codeLength";
	public static final String CODE_EXPIRATION_MINUTES = "codeExpirationMinutes";
	public static final String EMAIL_SUBJECT = "emailSubject";
	public static final String EMAIL_FROM = "emailFrom";
	public static final String RESEND_PARAM = "resendParam";

	private String loginPage;
	private String codeParam;
	private int codeLength;
	private int codeExpirationMinutes;
	private String emailSubject;
	private String emailFrom;
	private String resendParam;

	@Override
	public void configure(String schemeId, Properties config) {
		super.configure(schemeId, config);
		loginPage = config.getProperty(LOGIN_PAGE, "/loginEmail.htm");
		codeParam = config.getProperty(CODE_PARAM, "code");
		codeLength = AuthenticationUtil.getInteger(config.getProperty(CODE_LENGTH), 6);
		codeExpirationMinutes = AuthenticationUtil.getInteger(config.getProperty(CODE_EXPIRATION_MINUTES), 10);
		emailSubject = config.getProperty(EMAIL_SUBJECT, "authentication.email.subject");
		emailFrom = config.getProperty(EMAIL_FROM, "");
		resendParam = config.getProperty(RESEND_PARAM, "resend");
	}

	/**
	 * @return the name of the user property that stores the verified email address that a given code should be sent
	 */
	public String getVerifiedEmailUserPropertyName() {
		return "authentication." + getSchemeId() + ".verifiedEmail";
	}

	/**
	 * @return the verified email address for the given user, or an empty string if none is configured
	 */
	public String getVerifiedEmailForUser(User user) {
		return user.getUserProperty(getVerifiedEmailUserPropertyName(), "");
	}

	/**
	 * @see WebAuthenticationScheme#isUserConfigurationRequired(User)
	 */
	@Override
	public boolean isUserConfigurationRequired(User user) {
		String email = getVerifiedEmailForUser(user);
		return (StringUtils.isBlank(email) || !EmailValidator.getInstance().isValid(email));
	}

	@Override
	public String getChallengeUrl(AuthenticationSession session) {
		return loginPage;
	}

	@Override
	public AuthenticationCredentials getCredentials(AuthenticationSession session) {
		AuthenticationCredentials credentials = session.getUserLogin().getUnvalidatedCredentials(getSchemeId());
		if (credentials != null) {
			return credentials;
		}

		User candidateUser = session.getUserLogin().getUser();
		if (candidateUser == null) {
			throw new ContextAuthenticationException("authentication.error.candidateUserRequired");
		}

		String storedCode = (String) session.getHttpSession().getAttribute(getSessionCodeKey());
		Long storedExpiry = (Long) session.getHttpSession().getAttribute(getSessionExpiryKey());

		boolean codeExpired = storedExpiry == null || System.currentTimeMillis() > storedExpiry;
		boolean resendRequested = StringUtils.isNotBlank(session.getRequestParam(resendParam));

		if (storedCode == null || codeExpired || resendRequested) {
			storedCode = generateCode();
			storedExpiry = System.currentTimeMillis() + (codeExpirationMinutes * 60_000L);
			session.setHttpSessionAttribute(getSessionCodeKey(), storedCode);
			session.setHttpSessionAttribute(getSessionExpiryKey(), storedExpiry);
			sendCode(candidateUser, storedCode);
		}

		String submittedCode = session.getRequestParam(codeParam);
		if (StringUtils.isBlank(submittedCode)) {
			return null;
		}

		credentials = new EmailCredentials(candidateUser, submittedCode, storedCode, storedExpiry);
		session.getUserLogin().addUnvalidatedCredentials(credentials);
		return credentials;
	}

	@Override
	protected Authenticated authenticate(AuthenticationCredentials credentials, UserLogin userLogin) {
		// Ensure the credentials provided are of the expected type
		if (!(credentials instanceof EmailCredentials)) {
			throw new ContextAuthenticationException("authentication.error.incorrectCredentialsForScheme");
		}
		EmailCredentials c = (EmailCredentials) credentials;

		if (c.user == null) {
			throw new ContextAuthenticationException("authentication.error.candidateUserRequired");
		}
		if (StringUtils.isBlank(c.submittedCode)) {
			throw new ContextAuthenticationException("authentication.error.codeRequired");
		}
		if (userLogin.getUser() != null && !userLogin.getUser().equals(c.user)) {
			throw new ContextAuthenticationException("authentication.error.userDiffersFromCandidateUser");
		}
		if (c.expectedExpiry == null || System.currentTimeMillis() > c.expectedExpiry) {
			throw new ContextAuthenticationException("authentication.error.codeExpired");
		}
		if (!c.submittedCode.equals(c.expectedCode)) {
			throw new ContextAuthenticationException("authentication.error.invalidCredentials");
		}

		return new BasicAuthenticated(c.user, credentials.getAuthenticationScheme());
	}

	/**
	 * @return the session attribute key used to store the email code for this scheme
	 */
	protected String getSessionCodeKey() {
		return "authentication." + getSchemeId() + ".emailCode";
	}

	/**
	 * @return the session attribute key used to store the email code expiry for this scheme
	 */
	protected String getSessionExpiryKey() {
		return "authentication." + getSchemeId() + ".emailCodeExpiry";
	}

	/**
	 * Sends the one-time code to the user's email address via the OpenMRS MessageService
	 * @param user the user to send the code to
	 * @param code the code to send
	 * @throws ContextAuthenticationException if the user has no email or the message could not be sent
	 */
	protected void sendCode(User user, String code) {
		String email = getVerifiedEmailForUser(user);
		if (StringUtils.isBlank(email)) {
			throw new ContextAuthenticationException("authentication.error.noEmailConfiguredForUser");
		}
		try {
			Context.addProxyPrivilege(PrivilegeConstants.GET_GLOBAL_PROPERTIES);
			MessageSource messageSource = Context.getMessageSourceService().getActiveMessageSource();
			String subject = messageSource.getMessage(emailSubject, new Object[] {code}, Context.getLocale());
			Message message = Context.getMessageService().createMessage(email, emailFrom, subject, subject);
			Context.getMessageService().sendMessage(message);
		}
		catch (MessageException e) {
			throw new ContextAuthenticationException("authentication.error.emailSendFailed");
		}
		finally {
			Context.removeProxyPrivilege(PrivilegeConstants.GET_GLOBAL_PROPERTIES);
		}
	}

	/**
	 * @return a randomly generated numeric code of the configured length
	 */
	protected String generateCode() {
		int max = (int) Math.pow(10, codeLength);
		int code = new SecureRandom().nextInt(max);
		return String.format("%0" + codeLength + "d", code);
	}

	/**
	 * Credentials inner class, to enable access and visibility of credential details to be limited to scheme
	 */
	public class EmailCredentials implements AuthenticationCredentials {

		protected final User user;
		protected final String submittedCode;
		protected final String expectedCode;
		protected final Long expectedExpiry;

		protected EmailCredentials(User user, String submittedCode, String expectedCode, Long expectedExpiry) {
			this.user = user;
			this.submittedCode = submittedCode;
			this.expectedCode = expectedCode;
			this.expectedExpiry = expectedExpiry;
		}

		@Override
		public String getAuthenticationScheme() {
			return getSchemeId();
		}

		@Override
		public String getClientName() {
			return user == null ? null : user.getUsername();
		}
	}
}
