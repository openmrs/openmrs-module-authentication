package org.openmrs.module.authentication;

import org.junit.jupiter.api.Test;
import org.openmrs.User;
import org.openmrs.api.context.Authenticated;
import org.openmrs.api.context.AuthenticationScheme;
import org.openmrs.api.context.UsernamePasswordAuthenticationScheme;

import java.util.Properties;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;

public class DelegatingAuthenticationSchemeTest extends BaseAuthenticationTest {

	@Test
	public void shouldDefaultToUsernameAndPasswordAuthenticationScheme() {
		setRuntimeProperties(new Properties());
		DelegatingAuthenticationScheme scheme = new DelegatingAuthenticationScheme();
		AuthenticationScheme delegatedScheme = scheme.getDelegatedAuthenticationScheme();
		assertThat(delegatedScheme, notNullValue());
		assertThat(delegatedScheme.getClass(), equalTo(UsernamePasswordAuthenticationScheme.class));
	}

	@Test
	public void shouldAuthenticateWithConfigurableAuthenticationScheme() {
		User u = new User();
		u.setUsername("admin");
		Class<?> customSchemeType = TestAuthenticationScheme.class;
		AuthenticationConfig.setProperty(AuthenticationConfig.SCHEME, "custom");
		AuthenticationConfig.setProperty(AuthenticationConfig.SCHEME + ".custom.type", customSchemeType.getName());
		AuthenticationConfig.setProperty(AuthenticationConfig.SCHEME + ".custom.config.users", "admin");
		DelegatingAuthenticationScheme scheme = new DelegatingAuthenticationScheme();
		AuthenticationScheme delegatedScheme = scheme.getDelegatedAuthenticationScheme();
		assertThat(delegatedScheme, notNullValue());
		assertThat(delegatedScheme.getClass(), equalTo(customSchemeType));
		TestAuthenticationCredentials credentials = new TestAuthenticationCredentials("custom", u);
		Authenticated authenticated = delegatedScheme.authenticate(credentials);
		assertThat(authenticated.getAuthenticationScheme(), equalTo("custom"));
		assertThat(authenticated.getUser().getUsername(), equalTo("admin"));
	}
}
