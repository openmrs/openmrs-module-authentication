package org.openmrs.module.authentication.web;

import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import dev.samstevens.totp.util.Utils;
import org.openmrs.api.context.Context;
import org.openmrs.module.authentication.AuthenticationUtil;
import org.openmrs.module.authentication.AuthenticationConfig;
import org.openmrs.module.authentication.web.TotpAuthenticationScheme;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.openmrs.User;
import org.openmrs.util.Security;

import java.util.Properties;
import java.util.HashMap;
import java.util.Map;

@Controller
@RequestMapping("/rest/v1/authentication/totp")
public class TotpSecretController {

    /**
     * Endpoint to generate a new TOTP secret and its QR code.
     * Example: GET /openmrs/ws/rest/v1/authentication/totp/secret
     * @return JSON with the generated secret, QR code data URI, and a 'valid' field for frontend validation
     */
    @GetMapping(value = "/secret", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public Map<String, Object> generateSecret() {
        TotpAuthenticationScheme scheme = (TotpAuthenticationScheme) AuthenticationConfig.getAuthenticationScheme("totp");

        String secret = scheme.generateSecret();
        String label = "";
        if (Context.getAuthenticatedUser() != null && Context.getAuthenticatedUser().getUsername() != null) {
            label = Context.getAuthenticatedUser().getDisplayString();
        }
        String qrCodeUri = scheme.generateQrCodeUriForSecret(secret, label);

        Map<String, Object> response = new HashMap<>();
        response.put("secret", secret);
        response.put("qrCode", qrCodeUri);
        return response;
    }

    /**
     * Endpoint to validate a TOTP code for a given secret using server-side config.
     * Example: POST /openmrs/ws/rest/v1/authentication/totp/validate
     * Body: { "secret": "...", "code": "..." }
     * @return JSON with a 'valid' field indicating if the code is valid for the secret
     */
    @PostMapping(value = "/validate", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public Map<String, Object> validateCode(@RequestBody Map<String, String> payload) {
        String secret = payload.get("secret");
        String code = payload.get("code");
        TotpAuthenticationScheme scheme = (TotpAuthenticationScheme) AuthenticationConfig.getAuthenticationScheme("totp");
        boolean valid = scheme.verifyCode(secret, code);
        boolean saved = false;
        if (valid) {
            User user = Context.getAuthenticatedUser();
            if (user != null) {
                String propertyName = scheme.getSecretUserPropertyName();
                //String encryptedSecret = Security.encrypt(secret);
                user.setUserProperty(propertyName, secret);
                Context.getUserService().saveUser(user);
                saved = true;
            }
        }
        Map<String, Object> response = new HashMap<>();
        response.put("valid", valid);
        response.put("saved", saved);
        return response;
    }
} 