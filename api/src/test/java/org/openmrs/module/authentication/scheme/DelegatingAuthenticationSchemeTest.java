package org.openmrs.module.authentication.scheme;

import org.junit.jupiter.api.Test;
import org.openmrs.api.context.Authenticated;
import org.openmrs.api.context.AuthenticationScheme;
import org.openmrs.api.context.UsernamePasswordAuthenticationScheme;
import org.openmrs.module.authentication.AuthenticationConfig;
import org.openmrs.module.authentication.BaseAuthenticationTest;
import org.openmrs.module.authentication.TestAuthenticationScheme;
import org.openmrs.module.authentication.TestUsernamePasswordAuthenticationScheme;
import org.openmrs.module.authentication.credentials.BasicAuthenticationCredentials;

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
	public void shouldAuthenticateWithUsernamePasswordAuthenticationScheme() {
		Class<?> customSchemeType = TestUsernamePasswordAuthenticationScheme.class;
		AuthenticationConfig.setProperty(AuthenticationConfig.SCHEME, "custom");
		AuthenticationConfig.setProperty(AuthenticationConfig.SCHEME + ".custom.type", customSchemeType.getName());
		DelegatingAuthenticationScheme scheme = new DelegatingAuthenticationScheme();
		AuthenticationScheme delegatedScheme = scheme.getDelegatedAuthenticationScheme();
		assertThat(delegatedScheme, notNullValue());
		assertThat(delegatedScheme.getClass(), equalTo(customSchemeType));
		BasicAuthenticationCredentials credentials = new BasicAuthenticationCredentials("custom", "admin", "test");
		Authenticated authenticated = delegatedScheme.authenticate(credentials);
		assertThat(authenticated.getAuthenticationScheme(), equalTo("custom"));
		assertThat(authenticated.getUser().getUsername(), equalTo("admin"));
	}

	@Test
	public void shouldAuthenticateWithConfigurableAuthenticationScheme() {
		Class<?> customSchemeType = TestAuthenticationScheme.class;
		AuthenticationConfig.setProperty(AuthenticationConfig.SCHEME, "custom");
		AuthenticationConfig.setProperty(AuthenticationConfig.SCHEME + ".custom.type", customSchemeType.getName());
		AuthenticationConfig.setProperty(AuthenticationConfig.SCHEME + ".custom.config.users", "admin");
		DelegatingAuthenticationScheme scheme = new DelegatingAuthenticationScheme();
		AuthenticationScheme delegatedScheme = scheme.getDelegatedAuthenticationScheme();
		assertThat(delegatedScheme, notNullValue());
		assertThat(delegatedScheme.getClass(), equalTo(customSchemeType));
		BasicAuthenticationCredentials credentials = new BasicAuthenticationCredentials("custom", "admin", "test");
		Authenticated authenticated = delegatedScheme.authenticate(credentials);
		assertThat(authenticated.getAuthenticationScheme(), equalTo("custom"));
		assertThat(authenticated.getUser().getUsername(), equalTo("admin"));
	}
}
