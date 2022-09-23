package org.openmrs.module.authentication;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.Logger;
import org.apache.logging.log4j.core.layout.PatternLayout;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.openmrs.logging.MemoryAppender;

import java.util.Properties;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.notNullValue;

/**
 * Base class for non-context-sensitive Authentication tests
 * Sets up loggers to enable testing of logging events
 */
public abstract class BaseAuthenticationTest {

	protected Logger logger;
	protected MemoryAppender memoryAppender;

	@BeforeEach
	public void setup() {
		String pattern = "userId=%X{userId},username=%X{username},marker=%markerSimpleName,message=%m";
		PatternLayout layout = PatternLayout.newBuilder().withPattern(pattern).build();
		memoryAppender = MemoryAppender.newBuilder().setLayout(layout).build();
		memoryAppender.start();
		logger = (Logger) LogManager.getLogger(AuthenticationLogger.class);
		logger.setAdditive(false);
		logger.setLevel(Level.INFO);
		logger.addAppender(memoryAppender);
		AuthenticationLogger.clearContext();
		AuthenticationConfig.setConfig(new Properties());
	}

	@AfterEach
	public void teardown() {
		logger.removeAppender(memoryAppender);
		memoryAppender.stop();
		((Logger) LogManager.getRootLogger()).getContext().updateLoggers();
		memoryAppender = null;
		logger = null;
		AuthenticationLogger.clearContext();
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
