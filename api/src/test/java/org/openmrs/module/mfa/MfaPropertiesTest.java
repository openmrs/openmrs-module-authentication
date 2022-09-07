package org.openmrs.module.mfa;

import org.junit.Test;

import java.util.List;
import java.util.Properties;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.openmrs.module.mfa.MfaProperties.MFA_ENABLED;
import static org.openmrs.module.mfa.MfaProperties.MFA_UNAUTHENTICATED_URLS;

public class MfaPropertiesTest {

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
}
