package org.openmrs.module.authentication;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.Logger;
import org.apache.logging.log4j.core.layout.PatternLayout;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.openmrs.api.context.AuthenticationScheme;
import org.openmrs.api.context.Context;
import org.openmrs.api.context.UserContext;
import org.openmrs.logging.MemoryAppender;
import org.openmrs.util.OpenmrsConstants;
import org.openmrs.util.OpenmrsUtil;

import java.io.File;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.notNullValue;

/**
 * Base class for non-context-sensitive Authentication tests
 * Sets up loggers to enable testing of logging events
 */
public abstract class BaseAuthenticationTest {

	protected MemoryAppender memoryAppender;
	protected File appDataDir;
	protected File runtimePropertiesFile;

	@BeforeEach
	public void setup() {
		appDataDir = createAppDataDir();
		runtimePropertiesFile = new File(appDataDir, "openmrs-runtime.properties");
		runtimePropertiesFile.deleteOnExit();
		PatternLayout layout = PatternLayout.newBuilder().withPattern("%m").build();
		memoryAppender = MemoryAppender.newBuilder().setLayout(layout).build();
		memoryAppender.start();
		Logger logger = (Logger) LogManager.getLogger(UserLogin.class);
		logger.setAdditive(false);
		logger.setLevel(Level.INFO);
		logger.addAppender(memoryAppender);
		setRuntimeProperties(new HashMap<>());
	}

	protected File createAppDataDir() {
		try {
			File appDataDir = File.createTempFile(UUID.randomUUID().toString(), "");
			appDataDir.delete();
			appDataDir.mkdir();
			appDataDir.deleteOnExit();
			return appDataDir;
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	protected void setRuntimeProperties(Map<String, String> p) {
		Properties props = new Properties();
		props.putAll(p);

		if (runtimePropertiesFile != null && runtimePropertiesFile.exists()) {
			runtimePropertiesFile.delete();
		}
		props.setProperty(OpenmrsConstants.APPLICATION_DATA_DIRECTORY_RUNTIME_PROPERTY, appDataDir.getAbsolutePath());
		OpenmrsUtil.storeProperties(props, runtimePropertiesFile, "test");
		Context.setRuntimeProperties(props);
		AuthenticationConfig.reloadConfigFromRuntimeProperties("openmrs");
		setAuthenticationSchemeOnContext();
	}

	protected void setAuthenticationSchemeOnContext() {
		try {
			AuthenticationScheme scheme = AuthenticationConfig.getAuthenticationScheme();
			Field field = Context.class.getDeclaredField("authenticationScheme");
			field.setAccessible(true);
			field.set(null, scheme);
			Context.setUserContext(new UserContext(scheme));
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	@AfterEach
	public void teardown() {
		Logger logger = (Logger) LogManager.getLogger(UserLogin.class);
		logger.removeAppender(memoryAppender);
		memoryAppender.stop();
		((Logger) LogManager.getRootLogger()).getContext().updateLoggers();
		memoryAppender = null;

		UserLoginTracker.removeLoginFromThread();
		if (runtimePropertiesFile != null && runtimePropertiesFile.exists()) {
			runtimePropertiesFile.delete();
		}
		if (appDataDir != null && appDataDir.exists()) {
			appDataDir.delete();
		}
	}

	/**
	 * @param test if the last line logged by the AuthenticationLogger contains the given test, return true
	 */
	protected void assertLastLogContains(String test) {
		assertThat(memoryAppender.getLogLines(), notNullValue());
		int numLines = memoryAppender.getLogLines().size();
		assertThat(numLines, greaterThan(0));
		String line = memoryAppender.getLogLines().get(numLines-1);
		assertThat(line, containsString(test));
	}
}
