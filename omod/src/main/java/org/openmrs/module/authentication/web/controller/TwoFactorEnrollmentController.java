package org.openmrs.module.authentication.web.controller;

import org.openmrs.api.context.AuthenticationScheme;
import org.openmrs.module.authentication.AuthenticationConfig;
import org.openmrs.module.authentication.web.WebAuthenticationScheme;
import org.openmrs.module.webservices.rest.SimpleObject;
import org.openmrs.module.webservices.rest.web.v1_0.controller.BaseRestController;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

import javax.servlet.http.HttpServletRequest;

/**
 * REST Controller to manage Two-Factor Authentication enrollment and verification.
 */
@Controller
@RequestMapping(value = "/rest/v1/auth/{schemeId}")
public class TwoFactorEnrollmentController extends BaseRestController {
	
	@RequestMapping(method = RequestMethod.POST, value = "/enrollment")
	@ResponseBody
	public SimpleObject initiateEnrollment(@PathVariable("schemeId") String schemeId, HttpServletRequest request) {
		WebAuthenticationScheme authScheme = getWebAuthenticationScheme(schemeId);
		return authScheme.initiateEnrollment(request);
	}
	
	@RequestMapping(method = RequestMethod.POST, value = "/enrollment/verify")
	@ResponseBody
	public SimpleObject verifyEnrollment(@PathVariable("schemeId") String schemeId, @RequestBody SimpleObject payload, HttpServletRequest request) {
		WebAuthenticationScheme authScheme = getWebAuthenticationScheme(schemeId);
		return authScheme.verifyEnrollment(payload, request);
	}
	
	@ExceptionHandler(UnsupportedOperationException.class)
	@ResponseStatus(HttpStatus.METHOD_NOT_ALLOWED)
	@ResponseBody
	public SimpleObject handleUnsupportedException(UnsupportedOperationException exception) {
		SimpleObject error = new SimpleObject();
		error.put("message", exception.getMessage());
		return error;
	}
	
	private WebAuthenticationScheme getWebAuthenticationScheme(String schemeId) {
		AuthenticationScheme authScheme = AuthenticationConfig.getAuthenticationScheme(schemeId);
		if (authScheme instanceof WebAuthenticationScheme) {
			return (WebAuthenticationScheme) authScheme;
		}
		throw new IllegalArgumentException("Unsupported scheme type: " + schemeId);
	}
}
