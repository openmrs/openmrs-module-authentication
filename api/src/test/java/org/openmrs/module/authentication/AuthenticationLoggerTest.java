package org.openmrs.module.authentication;

import org.apache.logging.log4j.Marker;
import org.junit.jupiter.api.Test;
import org.openmrs.User;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

public class AuthenticationLoggerTest extends BaseAuthenticationTest {

	@Test
	public void shouldAddUserToContext() {
		User user = new User();
		user.setUserId(1234);
		user.setUsername("testing");
		AuthenticationLogger.addUserToContext(user);
		AuthenticationLogger.logEvent(AuthenticationLogger.LOGIN_SUCCEEDED);
		assertLastLogContains("userId=1234,username=testing,");
		AuthenticationLogger.addUserToContext(null);
		AuthenticationLogger.logEvent(AuthenticationLogger.LOGIN_SUCCEEDED);
		assertLastLogContains("userId=,username=,");
	}

	@Test
	public void shouldRemoveUserFromContext() {
		User user = new User();
		user.setUserId(1234);
		user.setUsername("testing");
		AuthenticationLogger.addUserToContext(user);
		AuthenticationLogger.logEvent(AuthenticationLogger.LOGIN_SUCCEEDED);
		assertLastLogContains("userId=1234,username=testing,");
		AuthenticationLogger.removeUserFromContext();
		AuthenticationLogger.logEvent(AuthenticationLogger.LOGIN_SUCCEEDED);
		assertLastLogContains("userId=,username=,");
	}

	@Test
	public void shouldAddToContext() {
		AuthenticationLogger.logEvent(AuthenticationLogger.LOGIN_SUCCEEDED);
		assertLastLogContains("userId=,username=,");
		AuthenticationLogger.addToContext("username", "admin");
		AuthenticationLogger.logEvent(AuthenticationLogger.LOGIN_SUCCEEDED);
		assertLastLogContains("userId=,username=admin,");
	}

	@Test
	public void shouldGetFromContext() {
		AuthenticationLogger.logEvent(AuthenticationLogger.LOGIN_SUCCEEDED);
		assertThat(AuthenticationLogger.getFromContext("username"), nullValue());
		AuthenticationLogger.addToContext("username", "admin");
		AuthenticationLogger.logEvent(AuthenticationLogger.LOGIN_SUCCEEDED);
		assertThat(AuthenticationLogger.getFromContext("username"), equalTo("admin"));
	}

	@Test
	public void shouldRemoveFromContext() {
		AuthenticationLogger.addToContext("username", "admin");
		AuthenticationLogger.logEvent(AuthenticationLogger.LOGIN_SUCCEEDED);
		assertThat(AuthenticationLogger.getFromContext("username"), equalTo("admin"));
		AuthenticationLogger.removeFromContext("username");
		AuthenticationLogger.logEvent(AuthenticationLogger.LOGIN_SUCCEEDED);
		assertThat(AuthenticationLogger.getFromContext("username"), nullValue());
	}

	@Test
	public void shouldClearContext() {
		AuthenticationLogger.addToContext("username", "admin");
		AuthenticationLogger.addToContext("userId", "1234");
		assertThat(AuthenticationLogger.getFromContext("username"), equalTo("admin"));
		assertThat(AuthenticationLogger.getFromContext("userId"), equalTo("1234"));
		AuthenticationLogger.clearContext();
		assertThat(AuthenticationLogger.getFromContext("username"), nullValue());
		assertThat(AuthenticationLogger.getFromContext("userId"), nullValue());
	}

	@Test
	public void shouldLogMessageAndMarker() {
		AuthenticationLogger.logEvent(AuthenticationLogger.LOGIN_SUCCEEDED, "Congratulations");
		assertLastLogContains("marker=AUTHENTICATION_LOGIN_SUCCEEDED,message=Congratulations");
	}

	@Test
	public void shouldLogMarker() {
		AuthenticationLogger.logEvent(AuthenticationLogger.LOGIN_SUCCEEDED);
		assertLastLogContains("marker=AUTHENTICATION_LOGIN_SUCCEEDED,message=AUTHENTICATION_LOGIN_SUCCEEDED");
	}

	@Test
	public void shouldGetMarker() {
		Marker marker = AuthenticationLogger.getMarker("TESTING");
		assertThat(marker.getName(), equalTo("TESTING"));
		assertThat(marker.getParents(), notNullValue());
		assertThat(marker.getParents().length, equalTo(1));
		assertThat(marker.getParents()[0], equalTo(AuthenticationLogger.AUTHENTICATION_EVENT_MARKER));
	}
}
