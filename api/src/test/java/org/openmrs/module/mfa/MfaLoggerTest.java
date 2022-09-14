package org.openmrs.module.mfa;

import org.junit.Test;

public class MfaLoggerTest {

	static {
		MfaProperties mfaProperties = new MfaProperties();
		mfaProperties.setProperty("mfa.logging.writerConsole", "console");
		mfaProperties.setProperty("mfa.logging.writerConsole.format", "{date: HH:mm:ss.SSS}: {message}");
		mfaProperties.setProperty("mfa.logging.writerFile", "console");
		mfaProperties.setProperty("mfa.logging.writerFile.format", "{context: sessionId} - {date: HH:mm:ss.SSS}: {message}");
		mfaProperties.setProperty("mfa.logging.writerFile.tag", "MFA");
		MfaLogger.initialize(mfaProperties);
	}

	@Test
	public void shouldConfigureLoggerAndAppender() {
		MfaLogger.addToContext("sessionId", "AAAAAAAAAAAAAAAAAAAAAAA");
		MfaLogger.logEvent(MfaLogger.Event.LOGIN_SUCCEEDED);
		MfaLogger.logEvent(MfaLogger.Event.PRIMARY_AUTH_FAILED, "test message");
		MfaLogger.clearContext();
	}
}
