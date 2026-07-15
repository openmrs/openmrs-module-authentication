/**
 * The contents of this file are subject to the OpenMRS Public License
 * Version 1.0 (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at
 * http://license.openmrs.org
 * <p>
 * Software distributed under the License is distributed on an "AS IS"
 * basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
 * License for the specific language governing rights and limitations
 * under the License.
 * <p>
 * Copyright (C) OpenMRS, LLC.  All Rights Reserved.
 */

package org.openmrs.module.authentication.web.controller;

import org.openmrs.User;
import org.openmrs.api.context.AuthenticationScheme;
import org.openmrs.api.context.Context;
import org.openmrs.module.authentication.AuthenticationConfig;
import org.openmrs.module.authentication.EnrollmentException;
import org.openmrs.module.authentication.web.EnrollableAuthenticationScheme;
import org.openmrs.module.authentication.web.TwoFactorAuthenticationScheme;
import org.openmrs.module.webservices.rest.SimpleObject;
import org.openmrs.module.webservices.rest.web.RestConstants;
import org.openmrs.module.webservices.rest.web.response.IllegalRequestException;
import org.openmrs.module.webservices.rest.web.response.ResourceDoesNotSupportOperationException;
import org.openmrs.module.webservices.rest.web.v1_0.controller.BaseRestController;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

/**
 * REST Controller to manage Two-Factor Authentication enrollment and verification.
 */
@Controller
@RequestMapping(value = "/rest/" + RestConstants.VERSION_1 + "/auth/{schemeId}")
public class TwoFactorEnrollmentController extends BaseRestController {
	
	@RequestMapping(method = RequestMethod.POST, value = "/enrollment")
	@ResponseBody
	public SimpleObject initiateEnrollment(@PathVariable("schemeId") String schemeId, HttpServletRequest request) {
		EnrollableAuthenticationScheme enrollableScheme = getEnrollableAuthenticationScheme(schemeId);
		try {
			challenge = enrollableScheme.initiateEnrollment(request);
		}
		catch (EnrollmentException e) {
			throw new IllegalRequestException(e.getMessage());
		}
		SimpleObject response = new SimpleObject();
		response.putAll(challenge);
		return response;
	}
	
	@RequestMapping(method = RequestMethod.POST, value = "/enrollment/verify")
	@ResponseBody
	public SimpleObject verifyEnrollment(@PathVariable("schemeId") String schemeId, @RequestBody SimpleObject payload,
			HttpServletRequest request) {
		EnrollableAuthenticationScheme enrollableScheme = getEnrollableAuthenticationScheme(schemeId);
		try {
			enrollableScheme.verifyEnrollment(payload, request);
			AuthenticationScheme twoFactor = AuthenticationConfig.getAuthenticationScheme();
			
			if (twoFactor instanceof TwoFactorAuthenticationScheme) {
				User user = Context.getAuthenticatedUser();
				((TwoFactorAuthenticationScheme) twoFactor).addSecondaryAuthenticationSchemeForUser(user, schemeId);
				String key = TwoFactorAuthenticationScheme.USER_PROPERTY_SECONDARY_TYPE;
				Context.getUserService().setUserProperty(user, key, user.getUserProperty(key));
			}
			
			SimpleObject response = new SimpleObject();
			response.put("isValidCode", true);
			return response;
		} catch (EnrollmentException e) {
			throw new IllegalRequestException(e.getMessage());
		}
	}
	
	private EnrollableAuthenticationScheme getEnrollableAuthenticationScheme(String schemeId) {
		AuthenticationScheme authScheme = AuthenticationConfig.getAuthenticationScheme(schemeId);
		
		if (!(authScheme instanceof EnrollableAuthenticationScheme)) {
			throw new ResourceDoesNotSupportOperationException("authentication.error.unsupportedSchemeType");
		}
		return (EnrollableAuthenticationScheme) authScheme;
	}
}
