package org.openmrs.module.authentication;

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
import static org.openmrs.module.authentication.AuthenticationConfig.AUTHENTICATORS_PRIMARY;
import static org.openmrs.module.authentication.AuthenticationConfig.AUTHENTICATORS_SECONDARY;
import static org.openmrs.module.authentication.AuthenticationConfig.FILTER_ENABLED;
import static org.openmrs.module.authentication.AuthenticationConfig.FILTER_SKIP_PATTERNS;
import static org.openmrs.module.authentication.AuthenticationConfig.SETTINGS_CACHED;

public class AuthenticationConfigTest extends BaseModuleContextSensitiveTest {

	@Before
	public void setup() {
		AuthenticationConfig.setConfig(new Properties());
	}

	@Test
	public void shouldGetAndSetKeysAndProperties() {
		AuthenticationConfig.setProperty(FILTER_ENABLED, "false");
		AuthenticationConfig.setProperty(FILTER_SKIP_PATTERNS, "*.css");
		assertThat(AuthenticationConfig.getKeys().size(), equalTo(2));
		assertThat(AuthenticationConfig.getProperty(FILTER_ENABLED), equalTo("false"));
		assertThat(AuthenticationConfig.getProperty(FILTER_SKIP_PATTERNS), equalTo("*.css"));
		assertThat(AuthenticationConfig.getProperty(SETTINGS_CACHED), nullValue());
		assertThat(AuthenticationConfig.getProperty(SETTINGS_CACHED, "true"), equalTo("true"));
		assertThat(AuthenticationConfig.getKeys().contains(FILTER_ENABLED), equalTo(true));
		assertThat(AuthenticationConfig.getKeys().contains(FILTER_SKIP_PATTERNS), equalTo(true));
		assertThat(AuthenticationConfig.getKeys().contains(SETTINGS_CACHED), equalTo(false));
	}

	@Test
	public void shouldGetBooleanProperty() {
		AuthenticationConfig.setProperty(FILTER_ENABLED, "false");
		assertThat(AuthenticationConfig.getBoolean(FILTER_ENABLED, true), equalTo(false));
		AuthenticationConfig.setProperty(FILTER_ENABLED, "true");
		assertThat(AuthenticationConfig.getBoolean(FILTER_ENABLED, false), equalTo(true));
	}

	@Test
	public void shouldGetStringListProperty() {
		assertThat(AuthenticationConfig.getStringList(FILTER_SKIP_PATTERNS).size(), equalTo(0));
		AuthenticationConfig.setProperty(FILTER_SKIP_PATTERNS, "*.css,*.gif,*.jpg,*.png");
		List<String> urls = AuthenticationConfig.getStringList(FILTER_SKIP_PATTERNS);
		assertThat(urls.size(), equalTo(4));
		assertThat(urls.get(0), equalTo("*.css"));
		assertThat(urls.get(1), equalTo("*.gif"));
		assertThat(urls.get(2), equalTo("*.jpg"));
		assertThat(urls.get(3), equalTo("*.png"));
	}

	@Test
	public void shouldGetClassInstance() {
		AuthenticationConfig.setProperty("user", "org.openmrs.User");
		User user = AuthenticationConfig.getClassInstance("user", User.class);
		assertThat(user, notNullValue());
		assertThat(user.getClass(), equalTo(User.class));
	}

	@Test
	public void shouldGetClass() {
		AuthenticationConfig.setProperty("user", "org.openmrs.User");
		Class<? extends User> userClass = AuthenticationConfig.getClass("user", User.class);
		assertThat(userClass, notNullValue());
		assertThat(userClass, equalTo(User.class));
	}

	@Test
	public void shouldGetPropertiesWithPrefix() {
		AuthenticationConfig.setProperty("prefs.color", "red");
		AuthenticationConfig.setProperty("prefs.season", "fall");
		AuthenticationConfig.setProperty("prefs.timeOfDay", "morning");
		AuthenticationConfig.setProperty("preferences.prefs.timeOfDay", "evening");
		{
			Properties p = AuthenticationConfig.getSubsetWithPrefix("prefs.", true);
			assertThat(p.size(), equalTo(3));
			assertThat(p.getProperty("prefs.color"), nullValue());
			assertThat(p.getProperty("prefs.season"), nullValue());
			assertThat(p.getProperty("prefs.timeOfDay"), nullValue());
			assertThat(p.getProperty("color"), equalTo("red"));
			assertThat(p.getProperty("season"), equalTo("fall"));
			assertThat(p.getProperty("timeOfDay"), equalTo("morning"));
		}
		{
			Properties p = AuthenticationConfig.getSubsetWithPrefix("prefs.", false);
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
	public void shouldGetFilterEnabled() {
		AuthenticationConfig.setProperty(FILTER_ENABLED, "false");
		assertThat(AuthenticationConfig.isFilterEnabled(), equalTo(false));
		AuthenticationConfig.setProperty(FILTER_ENABLED, "true");
		assertThat(AuthenticationConfig.isFilterEnabled(), equalTo(true));
	}

	@Test
	public void shouldGetConfigSettingsCached() {
		AuthenticationConfig.setProperty(SETTINGS_CACHED, "false");
		assertThat(AuthenticationConfig.isConfigurationCached(), equalTo(false));
		AuthenticationConfig.setProperty(SETTINGS_CACHED, "true");
		assertThat(AuthenticationConfig.isConfigurationCached(), equalTo(true));
	}

	@Test
	public void shouldGetFilterSkipPatterns() {
		AuthenticationConfig.setProperty(FILTER_SKIP_PATTERNS, "*.css,*.gif,*.jpg");
		List<String> patterns = AuthenticationConfig.getFilterSkipPatterns();
		assertThat(patterns.size(), equalTo(3));
		assertThat(patterns.get(0), equalTo("*.css"));
		assertThat(patterns.get(1), equalTo("*.gif"));
		assertThat(patterns.get(2), equalTo("*.jpg"));
	}

	@Test
	public void shouldGetPrimaryAuthenticatorOptions() {
		AuthenticationConfig.setProperty(AUTHENTICATORS_PRIMARY, "basic,sms");
		List<String> options = AuthenticationConfig.getPrimaryAuthenticatorOptions();
		assertThat(options.size(), equalTo(2));
		assertThat(options.get(0), equalTo("basic"));
		assertThat(options.get(1), equalTo("sms"));
	}

	@Test
	public void shouldGetSecondaryAuthenticatorOptions() {
		AuthenticationConfig.setProperty(AUTHENTICATORS_SECONDARY, "basic,sms");
		List<String> options = AuthenticationConfig.getSecondaryAuthenticatorOptions();
		assertThat(options.size(), equalTo(2));
		assertThat(options.get(0), equalTo("basic"));
		assertThat(options.get(1), equalTo("sms"));
	}

	@Test
	public void shouldGetDefaultPrimaryAuthenticator() {
		AuthenticationConfig.setProperty(AUTHENTICATORS_PRIMARY, "basic,sms");
		AuthenticationConfig.setProperty("authentication.authenticator.basic.type", "org.openmrs.module.authentication.TestAuthenticator");
		Authenticator authenticator = AuthenticationConfig.getDefaultPrimaryAuthenticator();
		assertThat(authenticator, notNullValue());
		assertThat(authenticator.getClass(), equalTo(TestAuthenticator.class));
	}

	@Test
	public void shouldGetAuthenticator() {
		AuthenticationConfig.setProperty(AUTHENTICATORS_PRIMARY, "basic,sms");
		AuthenticationConfig.setProperty("authentication.authenticator.sms.type", "org.openmrs.module.authentication.TestAuthenticator");
		Authenticator authenticator = AuthenticationConfig.getAuthenticator("sms");
		assertThat(authenticator, notNullValue());
		assertThat(authenticator.getClass(), equalTo(TestAuthenticator.class));
	}
}
