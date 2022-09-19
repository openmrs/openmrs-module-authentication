package org.openmrs.module.authentication;

import org.junit.Test;

public class AuthenticationLoggerTest {

	@Test
	public void shouldConfigureLoggerAndAppender() {
		AuthenticationLogger.addToContext("sessionId", "AAAAAAAAAAAAAAAAAAAAAAA");
		AuthenticationLogger.logEvent(AuthenticationLogger.Event.AUTHENTICATION_LOGIN_SUCCEEDED);
		AuthenticationLogger.logEvent(AuthenticationLogger.Event.AUTHENTICATION_PRIMARY_AUTH_FAILED, "test message");
		AuthenticationLogger.clearContext();
	}
}
