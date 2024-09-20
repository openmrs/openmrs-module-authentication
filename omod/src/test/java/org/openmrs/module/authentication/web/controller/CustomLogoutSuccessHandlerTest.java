package org.openmrs.module.authentication.web.controller;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.mockito.internal.verification.api.VerificationData;
import org.openmrs.api.context.Context;
import org.openmrs.module.authentication.web.HttpUtils;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.web.RedirectStrategy;
import org.mockito.MockedStatic;
import static org.mockito.Mockito.mockStatic;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.mockito.Mockito.*;

@RunWith(PowerMockRunner.class)
@PowerMockIgnore("javax.management.*")
@PrepareForTest(Context.class)
public class CustomLogoutSuccessHandlerTest {
	
	public CustomLogoutSuccessHandlerTest() {
		OAuth2IntegrationTest.initPathInSystemProperties("Keycloak");
	}

	@Test
	public void onLogoutSuccess_redirectToLogoutURL() throws IOException, ServletException {
		// Setup:
		PowerMockito.mockStatic(Context.class);

		CustomLogoutSuccessHandler customLogoutSuccessHandler = new CustomLogoutSuccessHandler();
		RedirectStrategy redirectStrategy = mock(RedirectStrategy.class);
		customLogoutSuccessHandler.setRedirectStrategy(redirectStrategy);

		MockHttpServletRequest request = new MockHttpServletRequest();
		HttpServletResponse response = mock(HttpServletResponse.class);
		OAuth2RestOperations restTemplate = mock(OAuth2RestOperations.class);
		customLogoutSuccessHandler.setRestTemplate(restTemplate);

		when(restTemplate.getAccessToken()).thenReturn(new DefaultOAuth2AccessToken("myToken"));

		customLogoutSuccessHandler.onLogoutSuccess(request, response, null);

		// Verify
		PowerMockito.verifyStatic(Context.class, times(1));
		Context.logout();

		verify(redirectStrategy, times(1)).sendRedirect(request, response,
				"http://localhost:8081/auth/realms/demo/protocol/openid-connect/logout?id_token_hint=myToken");
	}
}
