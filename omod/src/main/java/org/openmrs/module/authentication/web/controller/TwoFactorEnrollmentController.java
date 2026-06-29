package org.openmrs.module.authentication.web.controller;

import org.openmrs.User;
import org.openmrs.api.context.AuthenticationScheme;
import org.openmrs.api.context.Context;
import org.openmrs.module.authentication.AuthenticationConfig;
import org.openmrs.module.authentication.web.TotpAuthenticationScheme;
import org.openmrs.module.webservices.rest.SimpleObject;
import org.openmrs.module.webservices.rest.web.v1_0.controller.BaseRestController;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;

@Controller
@RequestMapping(value = "/rest/v1/auth/{schemeId}")
public class TwoFactorEnrollmentController extends BaseRestController {
	
	@RequestMapping(method = RequestMethod.POST, value = "/enrollment")
	@ResponseBody
	public SimpleObject initiateEnrollment(@PathVariable("schemeId") String schemeId, HttpServletRequest request) {
		TotpAuthenticationScheme totpScheme = getTotpScheme(schemeId);
		User user = Context.getAuthenticatedUser();
		
		String newSecret = totpScheme.generateSecret();
		String newQrCodeUri = totpScheme.generateQrCodeUriForSecret(newSecret, user.getUsername());
		
		request.getSession().setAttribute("totp_temporary_secret", newSecret);
		
		SimpleObject response = new SimpleObject();
		response.put("newSecret", newSecret);
		response.put("newQrCodeUri", newQrCodeUri);
		return response;
	}
	
	@RequestMapping(method = RequestMethod.POST, value = "/enrollment/verify")
	@ResponseBody
	public SimpleObject verifyEnrollment(@PathVariable("schemeId") String schemeId, @RequestParam("code") String code, HttpServletRequest request) {
		TotpAuthenticationScheme totpScheme = getTotpScheme(schemeId);
		User user = Context.getAuthenticatedUser();
		
		String temporarySavedSecret = (String) request.getSession().getAttribute("totp_temporary_secret");
		if (temporarySavedSecret == null) {
			throw new IllegalArgumentException("Session Expired");
		}
		
		boolean isValidCode = totpScheme.verifyCode(temporarySavedSecret, code);
		if (!isValidCode) {
			throw new IllegalArgumentException("Invalid code Entered");
		}
		
		SimpleObject response = new SimpleObject();
		response.put("isValidCode", isValidCode);
		return response;
	}
	
	private TotpAuthenticationScheme getTotpScheme(String schemeId) {
		AuthenticationScheme authScheme = AuthenticationConfig.getAuthenticationScheme(schemeId);
		if (authScheme instanceof TotpAuthenticationScheme) {
			return (TotpAuthenticationScheme) authScheme;
		}
		throw new IllegalArgumentException("Must be a TOTP scheme: " + schemeId);
	}
}
