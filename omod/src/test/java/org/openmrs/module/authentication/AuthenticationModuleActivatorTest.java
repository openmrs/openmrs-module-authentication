package org.openmrs.module.authentication;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class AuthenticationModuleActivatorTest extends BaseAuthenticationTest {

	Logger logger = (Logger) LogManager.getLogger(AuthenticationModuleActivator.class);

	@BeforeEach
	@Override
	public void setup() {
		super.setup();
		logger.setAdditive(false);
		logger.setLevel(Level.INFO);
		logger.addAppender(memoryAppender);
	}

	@AfterEach
	@Override
	public void teardown() {
		logger.removeAppender(memoryAppender);
		super.teardown();
	}

	@Test
	public void shouldLogAtStartupAndShutdown() {
		AuthenticationModuleActivator activator = new AuthenticationModuleActivator();
		activator.started();
		assertLastLogContains("Authentication Module Started");
		activator.stopped();
		assertLastLogContains("Authentication Module Stopped");
	}

}
