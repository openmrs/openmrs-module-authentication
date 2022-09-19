package org.openmrs.module.mfa;

import org.junit.Before;
import org.junit.Test;
import org.openmrs.User;
import org.openmrs.test.jupiter.BaseModuleContextSensitiveTest;

import java.util.List;
import java.util.Properties;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.openmrs.module.mfa.MfaProperties.AUTHENTICATORS_PRIMARY;
import static org.openmrs.module.mfa.MfaProperties.AUTHENTICATORS_SECONDARY;
import static org.openmrs.module.mfa.MfaProperties.MFA_DISABLE_CONFIGURATION_CACHE;
import static org.openmrs.module.mfa.MfaProperties.MFA_ENABLED;
import static org.openmrs.module.mfa.MfaProperties.MFA_UNAUTHENTICATED_URLS;

public class MfaPropertiesTest extends BaseModuleContextSensitiveTest {

	@Before
	public void setup() {
		MfaProperties.setConfig(new Properties());
	}

	@Test
	public void shouldGetAndSetKeysAndProperties() {
		MfaProperties.setProperty(MFA_ENABLED, "false");
		MfaProperties.setProperty(MFA_UNAUTHENTICATED_URLS, "*.css");
		assertThat(MfaProperties.getKeys().size(), equalTo(2));
		assertThat(MfaProperties.getProperty(MFA_ENABLED), equalTo("false"));
		assertThat(MfaProperties.getProperty(MFA_UNAUTHENTICATED_URLS), equalTo("*.css"));
		assertThat(MfaProperties.getProperty(MFA_DISABLE_CONFIGURATION_CACHE), nullValue());
		assertThat(MfaProperties.getProperty(MFA_DISABLE_CONFIGURATION_CACHE, "true"), equalTo("true"));
		assertThat(MfaProperties.getKeys().contains(MFA_ENABLED), equalTo(true));
		assertThat(MfaProperties.getKeys().contains(MFA_UNAUTHENTICATED_URLS), equalTo(true));
		assertThat(MfaProperties.getKeys().contains(MFA_DISABLE_CONFIGURATION_CACHE), equalTo(false));
	}

	@Test
	public void shouldGetBooleanProperty() {
		MfaProperties.setProperty(MFA_ENABLED, "false");
		assertThat(MfaProperties.getBoolean(MFA_ENABLED, true), equalTo(false));
		MfaProperties.setProperty(MFA_ENABLED, "true");
		assertThat(MfaProperties.getBoolean(MFA_ENABLED, false), equalTo(true));
	}

	@Test
	public void shouldGetStringListProperty() {
		assertThat(MfaProperties.getStringList(MFA_UNAUTHENTICATED_URLS).size(), equalTo(0));
		MfaProperties.setProperty(MFA_UNAUTHENTICATED_URLS, "*.css,*.gif,*.jpg,*.png");
		List<String> urls = MfaProperties.getStringList(MFA_UNAUTHENTICATED_URLS);
		assertThat(urls.size(), equalTo(4));
		assertThat(urls.get(0), equalTo("*.css"));
		assertThat(urls.get(1), equalTo("*.gif"));
		assertThat(urls.get(2), equalTo("*.jpg"));
		assertThat(urls.get(3), equalTo("*.png"));
	}

	@Test
	public void shouldGetClassInstance() {
		MfaProperties.setProperty("user", "org.openmrs.User");
		User user = MfaProperties.getClassInstance("user", User.class);
		assertThat(user, notNullValue());
		assertThat(user.getClass(), equalTo(User.class));
	}

	@Test
	public void shouldGetClass() {
		MfaProperties.setProperty("user", "org.openmrs.User");
		Class<? extends User> userClass = MfaProperties.getClass("user", User.class);
		assertThat(userClass, notNullValue());
		assertThat(userClass, equalTo(User.class));
	}

	@Test
	public void shouldGetPropertiesWithPrefix() {
		MfaProperties.setProperty("prefs.color", "red");
		MfaProperties.setProperty("prefs.season", "fall");
		MfaProperties.setProperty("prefs.timeOfDay", "morning");
		MfaProperties.setProperty("preferences.prefs.timeOfDay", "evening");
		{
			Properties p = MfaProperties.getSubsetWithPrefix("prefs.", true);
			assertThat(p.size(), equalTo(3));
			assertThat(p.getProperty("prefs.color"), nullValue());
			assertThat(p.getProperty("prefs.season"), nullValue());
			assertThat(p.getProperty("prefs.timeOfDay"), nullValue());
			assertThat(p.getProperty("color"), equalTo("red"));
			assertThat(p.getProperty("season"), equalTo("fall"));
			assertThat(p.getProperty("timeOfDay"), equalTo("morning"));
		}
		{
			Properties p = MfaProperties.getSubsetWithPrefix("prefs.", false);
			assertThat(p.size(), equalTo(3));
			assertThat(p.getProperty("prefs.color"), equalTo("red"));
			assertThat(p.getProperty("prefs.season"), equalTo("fall"));
			assertThat(p.getProperty("prefs.timeOfDay"), equalTo("morning"));
			assertThat(p.getProperty("color"), nullValue());
			assertThat(p.getProperty("season"), nullValue());
			assertThat(p.getProperty("timeOfDay"), nullValue());
		}
	}

	@Test
	public void shouldGetMfaEnabled() {
		MfaProperties.setProperty(MFA_ENABLED, "false");
		assertThat(MfaProperties.isMfaEnabled(), equalTo(false));
		MfaProperties.setProperty(MFA_ENABLED, "true");
		assertThat(MfaProperties.isMfaEnabled(), equalTo(true));
	}

	@Test
	public void shouldGetDisableConfigurationCache() {
		MfaProperties.setProperty(MFA_DISABLE_CONFIGURATION_CACHE, "true");
		assertThat(MfaProperties.isConfigurationCacheDisabled(), equalTo(true));
		MfaProperties.setProperty(MFA_DISABLE_CONFIGURATION_CACHE, "false");
		assertThat(MfaProperties.isConfigurationCacheDisabled(), equalTo(false));
	}

	@Test
	public void shouldGetUnauthenticatedUrlPatterns() {
		MfaProperties.setProperty(MFA_UNAUTHENTICATED_URLS, "*.css,*.gif,*.jpg");
		List<String> patterns = MfaProperties.getUnauthenticatedUrlPatterns();
		assertThat(patterns.size(), equalTo(3));
		assertThat(patterns.get(0), equalTo("*.css"));
		assertThat(patterns.get(1), equalTo("*.gif"));
		assertThat(patterns.get(2), equalTo("*.jpg"));
	}

	@Test
	public void shouldGetPrimaryAuthenticatorOptions() {
		MfaProperties.setProperty(AUTHENTICATORS_PRIMARY, "basic,sms");
		List<String> options = MfaProperties.getPrimaryAuthenticatorOptions();
		assertThat(options.size(), equalTo(2));
		assertThat(options.get(0), equalTo("basic"));
		assertThat(options.get(1), equalTo("sms"));
	}

	@Test
	public void shouldGetSecondaryAuthenticatorOptions() {
		MfaProperties.setProperty(AUTHENTICATORS_SECONDARY, "basic,sms");
		List<String> options = MfaProperties.getSecondaryAuthenticatorOptions();
		assertThat(options.size(), equalTo(2));
		assertThat(options.get(0), equalTo("basic"));
		assertThat(options.get(1), equalTo("sms"));
	}

	@Test
	public void shouldGetDefaultPrimaryAuthenticator() {
		MfaProperties.setProperty(AUTHENTICATORS_PRIMARY, "basic,sms");
		MfaProperties.setProperty("mfa.authenticator.basic.type", "org.openmrs.module.mfa.TestAuthenticator");
		Authenticator authenticator = MfaProperties.getDefaultPrimaryAuthenticator();
		assertThat(authenticator, notNullValue());
		assertThat(authenticator.getClass(), equalTo(TestAuthenticator.class));
	}

	@Test
	public void shouldGetAuthenticator() {
		MfaProperties.setProperty(AUTHENTICATORS_PRIMARY, "basic,sms");
		MfaProperties.setProperty("mfa.authenticator.sms.type", "org.openmrs.module.mfa.TestAuthenticator");
		Authenticator authenticator = MfaProperties.getAuthenticator("sms");
		assertThat(authenticator, notNullValue());
		assertThat(authenticator.getClass(), equalTo(TestAuthenticator.class));
	}
}
