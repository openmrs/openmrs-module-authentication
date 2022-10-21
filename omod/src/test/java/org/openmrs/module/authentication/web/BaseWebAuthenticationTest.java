package org.openmrs.module.authentication.web;

import org.junit.jupiter.api.BeforeEach;
import org.openmrs.module.authentication.AuthenticationContext;
import org.openmrs.module.authentication.BaseAuthenticationTest;
import org.springframework.mock.web.MockFilterConfig;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.mock.web.MockServletContext;

import javax.servlet.http.HttpSession;

/**
 * Base class for web-based, non-context-sensitive Authentication tests
 */
public abstract class BaseWebAuthenticationTest extends BaseAuthenticationTest {

	private MockServletContext servletContext;

	@Override
	@BeforeEach
	public void setup() {
		super.setup();
		servletContext = new MockServletContext();

	}

	protected MockHttpServletRequest newGetRequest(String uri, String ipAddress) {
		MockHttpServletRequest request = new MockHttpServletRequest(servletContext, "GET", uri);
		request.setRemoteAddr(ipAddress);
		return request;
	}

	protected MockHttpServletRequest newPostRequest(String ipAddress, String uri) {
		MockHttpServletRequest request = new MockHttpServletRequest(servletContext, "POST", uri);
		request.setRemoteAddr(ipAddress);
		return request;
	}

	protected MockHttpServletResponse newResponse() {
		return new MockHttpServletResponse();
	}

	protected MockHttpSession newSession() {
		return new MockHttpSession(servletContext);
	}

	protected MockHttpSession newSession(String username) {
		MockHttpSession session = newSession();
		AuthenticationContext context = new AuthenticationContext();
		context.setUsername(username);
		setAuthenticationContext(session, context);
		return session;
	}

	protected MockFilterConfig newFilterConfig(String filterName) {
		return new MockFilterConfig(servletContext, filterName);
	}

	protected AuthenticationContext getAuthenticationContext(HttpSession session) {
		return (AuthenticationContext) session.getAttribute(AuthenticationSession.AUTHENTICATION_CONTEXT_KEY);
	}

	protected void setAuthenticationContext(HttpSession session, AuthenticationContext context) {
		session.setAttribute(AuthenticationSession.AUTHENTICATION_CONTEXT_KEY, context);
	}
}
