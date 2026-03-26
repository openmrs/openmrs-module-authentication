package org.openmrs.module.authentication.web.controller;

import org.openmrs.User;
import org.openmrs.api.context.AuthenticationScheme;
import org.openmrs.api.context.Context;
import org.openmrs.module.authentication.DelegatingAuthenticationScheme;
import org.openmrs.module.authentication.web.AuthenticationSession;
import org.openmrs.module.authentication.web.TotpAuthenticationScheme;
import org.openmrs.module.authentication.web.TwoFactorAuthenticationScheme;
import org.openmrs.module.authentication.web.WebAuthenticationScheme;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Collections;
import java.util.Map;

@Controller
@RequestMapping("/rest/v1/authentication")
public class AuthenticationRestController {

    @RequestMapping(value = "/totp", method = RequestMethod.POST)
    @ResponseBody
    public ResponseEntity<Object> validateTotp(@RequestBody Map<String, String> body, HttpServletRequest request, HttpServletResponse response) {
        String code = body.get("code");
        AuthenticationSession session = new AuthenticationSession(request, response);
        User candidateUser = session.getUserLogin().getUser();

        if (candidateUser == null) {
            return new ResponseEntity<>(Collections.singletonMap("error", "No candidate user found in session"), HttpStatus.BAD_REQUEST);
        }

        AuthenticationScheme activeScheme = Context.getAuthenticationScheme();
        if (activeScheme instanceof DelegatingAuthenticationScheme) {
            activeScheme = ((DelegatingAuthenticationScheme) activeScheme).getDelegatedAuthenticationScheme();
        }

        if (activeScheme instanceof TwoFactorAuthenticationScheme) {
            TwoFactorAuthenticationScheme mfa = (TwoFactorAuthenticationScheme) activeScheme;
            WebAuthenticationScheme secondaryScheme = mfa.getSecondaryAuthenticationScheme(candidateUser);
            if (secondaryScheme instanceof TotpAuthenticationScheme) {
                try {
                    session.authenticate(secondaryScheme, ((TotpAuthenticationScheme) secondaryScheme).new TotpCredentials(candidateUser, code));
                    return new ResponseEntity<>(Collections.singletonMap("authenticated", true), HttpStatus.OK);
                } catch (Exception e) {
                    return new ResponseEntity<>(Collections.singletonMap("error", e.getMessage()), HttpStatus.UNAUTHORIZED);
                }
            }
        }
        return new ResponseEntity<>(Collections.singletonMap("error", "MFA or TOTP not active for this user"), HttpStatus.BAD_REQUEST);
    }
}
