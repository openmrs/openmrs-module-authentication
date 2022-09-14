package org.openmrs.module.mfa;

import org.junit.Test;
import org.openmrs.User;
import org.openmrs.util.OpenmrsUtil;

import java.io.File;
import java.io.FileOutputStream;
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
import static org.openmrs.module.mfa.MfaProperties.MFA_PROPERTIES_FILE_NAME;
import static org.openmrs.module.mfa.MfaProperties.MFA_UNAUTHENTICATED_URLS;

public class MfaPropertiesTest {

	@Test
	public void shouldGetAndSetKeysAndProperties() {
		MfaProperties config = new MfaProperties(new Properties());
		config.setProperty(MFA_ENABLED, "false");
		config.setProperty(MFA_UNAUTHENTICATED_URLS, "*.css");
		assertThat(config.getConfig().size(), equalTo(2));
		assertThat(config.getProperty(MFA_ENABLED), equalTo("false"));
		assertThat(config.getProperty(MFA_UNAUTHENTICATED_URLS), equalTo("*.css"));
		assertThat(config.getProperty(MFA_DISABLE_CONFIGURATION_CACHE), nullValue());
		assertThat(config.getProperty(MFA_DISABLE_CONFIGURATION_CACHE, "true"), equalTo("true"));
		assertThat(config.getKeys().size(), equalTo(2));
		assertThat(config.getKeys().contains(MFA_ENABLED), equalTo(true));
		assertThat(config.getKeys().contains(MFA_UNAUTHENTICATED_URLS), equalTo(true));
		assertThat(config.getKeys().contains(MFA_DISABLE_CONFIGURATION_CACHE), equalTo(false));
	}

	@Test
	public void shouldGetBooleanProperty() {
		MfaProperties config = new MfaProperties(new Properties());
		config.setProperty(MFA_ENABLED, "false");
		assertThat(config.getBoolean(MFA_ENABLED, true), equalTo(false));
		config.setProperty(MFA_ENABLED, "true");
		assertThat(config.getBoolean(MFA_ENABLED, false), equalTo(true));
	}

	@Test
	public void shouldGetStringListProperty() {
		MfaProperties config = new MfaProperties(new Properties());
		assertThat(config.getStringList(MFA_UNAUTHENTICATED_URLS).size(), equalTo(0));
		config.setProperty(MFA_UNAUTHENTICATED_URLS, "*.css,*.gif,*.jpg,*.png");
		List<String> urls = config.getStringList(MFA_UNAUTHENTICATED_URLS);
		assertThat(urls.size(), equalTo(4));
		assertThat(urls.get(0), equalTo("*.css"));
		assertThat(urls.get(1), equalTo("*.gif"));
		assertThat(urls.get(2), equalTo("*.jpg"));
		assertThat(urls.get(3), equalTo("*.png"));
	}

	@Test
	public void shouldGetClassInstance() {
		MfaProperties config = new MfaProperties(new Properties());
		config.setProperty("user", "org.openmrs.User");
		User user = config.getClassInstance("user", User.class);
		assertThat(user, notNullValue());
		assertThat(user.getClass(), equalTo(User.class));
	}

	@Test
	public void shouldGetClass() {
		MfaProperties config = new MfaProperties(new Properties());
		config.setProperty("user", "org.openmrs.User");
		Class<? extends User> userClass = config.getClass("user", User.class);
		assertThat(userClass, notNullValue());
		assertThat(userClass, equalTo(User.class));
	}

	@Test
	public void shouldGetPropertiesWithPrefix() {
		MfaProperties config = new MfaProperties(new Properties());
		config.setProperty("prefs.color", "red");
		config.setProperty("prefs.season", "fall");
		config.setProperty("prefs.timeOfDay", "morning");
		config.setProperty("preferences.prefs.timeOfDay", "evening");
		{
			Properties p = config.getSubsetWithPrefix("prefs.", true);
			assertThat(p.size(), equalTo(3));
			assertThat(p.getProperty("prefs.color"), nullValue());
			assertThat(p.getProperty("prefs.season"), nullValue());
			assertThat(p.getProperty("prefs.timeOfDay"), nullValue());
			assertThat(p.getProperty("color"), equalTo("red"));
			assertThat(p.getProperty("season"), equalTo("fall"));
			assertThat(p.getProperty("timeOfDay"), equalTo("morning"));
		}
		{
			Properties p = config.getSubsetWithPrefix("prefs.", false);
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
		MfaProperties config = new MfaProperties(new Properties());
		config.setProperty(MFA_ENABLED, "false");
		assertThat(config.isMfaEnabled(), equalTo(false));
		config.setProperty(MFA_ENABLED, "true");
		assertThat(config.isMfaEnabled(), equalTo(true));
	}

	@Test
	public void shouldGetDisableConfigurationCache() {
		MfaProperties config = new MfaProperties(new Properties());
		config.setProperty(MFA_DISABLE_CONFIGURATION_CACHE, "true");
		assertThat(config.isConfigurationCacheDisabled(), equalTo(true));
		config.setProperty(MFA_DISABLE_CONFIGURATION_CACHE, "false");
		assertThat(config.isConfigurationCacheDisabled(), equalTo(false));
	}

	@Test
	public void shouldGetUnauthenticatedUrlPatterns() {
		MfaProperties config = new MfaProperties(new Properties());
		config.setProperty(MFA_UNAUTHENTICATED_URLS, "*.css,*.gif,*.jpg");
		List<String> patterns = config.getUnauthenticatedUrlPatterns();
		assertThat(patterns.size(), equalTo(3));
		assertThat(patterns.get(0), equalTo("*.css"));
		assertThat(patterns.get(1), equalTo("*.gif"));
		assertThat(patterns.get(2), equalTo("*.jpg"));
	}

	@Test
	public void shouldGetPrimaryAuthenticatorOptions() {
		MfaProperties config = new MfaProperties(new Properties());
		config.setProperty(AUTHENTICATORS_PRIMARY, "basic,sms");
		List<String> options = config.getPrimaryAuthenticatorOptions();
		assertThat(options.size(), equalTo(2));
		assertThat(options.get(0), equalTo("basic"));
		assertThat(options.get(1), equalTo("sms"));
	}

	@Test
	public void shouldGetSecondaryAuthenticatorOptions() {
		MfaProperties config = new MfaProperties(new Properties());
		config.setProperty(AUTHENTICATORS_SECONDARY, "basic,sms");
		List<String> options = config.getSecondaryAuthenticatorOptions();
		assertThat(options.size(), equalTo(2));
		assertThat(options.get(0), equalTo("basic"));
		assertThat(options.get(1), equalTo("sms"));
	}

	@Test
	public void shouldGetDefaultPrimaryAuthenticator() {
		MfaProperties config = new MfaProperties(new Properties());
		config.setProperty(AUTHENTICATORS_PRIMARY, "basic,sms");
		config.setProperty("authenticator.basic.type", "org.openmrs.module.mfa.TestAuthenticator");
		Authenticator authenticator = config.getDefaultPrimaryAuthenticator();
		assertThat(authenticator, notNullValue());
		assertThat(authenticator.getClass(), equalTo(TestAuthenticator.class));
	}

	@Test
	public void shouldGetAuthenticator() {
		MfaProperties config = new MfaProperties(new Properties());
		config.setProperty(AUTHENTICATORS_PRIMARY, "basic,sms");
		config.setProperty("authenticator.sms.type", "org.openmrs.module.mfa.TestAuthenticator");
		Authenticator authenticator = config.getAuthenticator("sms");
		assertThat(authenticator, notNullValue());
		assertThat(authenticator.getClass(), equalTo(TestAuthenticator.class));
	}

	@Test
	public void shouldGetPropertiesFromFile() throws Exception {
		File file = new File(OpenmrsUtil.getApplicationDataDirectory(), MFA_PROPERTIES_FILE_NAME);
		file.deleteOnExit();
		Properties p = new Properties();
		p.setProperty(MFA_ENABLED, "false");
		p.setProperty(MFA_UNAUTHENTICATED_URLS, "*.css");
		p.store(new FileOutputStream(file), "");
		MfaProperties config = new MfaProperties();
		assertThat(config.getKeys().size(), equalTo(2));
		assertThat(config.getProperty(MFA_ENABLED), equalTo("false"));
		assertThat(config.getProperty(MFA_UNAUTHENTICATED_URLS), equalTo("*.css"));
	}
}
