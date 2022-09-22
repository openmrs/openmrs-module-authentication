package org.openmrs.module.authentication;

import org.junit.jupiter.api.Test;

public class AuthenticationModuleActivatorTest extends BaseAuthenticationTest {

	@Test
	public void shouldLogAtStartupAndShutdown() {
		AuthenticationModuleActivator activator = new AuthenticationModuleActivator();
		activator.started();
		assertLastLogContains("marker=AUTHENTICATION_MODULE_STARTED,message=AUTHENTICATION_MODULE_STARTED");
		activator.stopped();
		assertLastLogContains("marker=AUTHENTICATION_MODULE_STOPPED,message=AUTHENTICATION_MODULE_STOPPED");
	}
}
