/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 * <p>
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.authentication.web.mocks;

import org.openmrs.User;
import org.openmrs.module.authentication.web.TwoFactorAuthenticationScheme;

/**
 * Test double that bypasses Context-backed persistence of remember-me tokens.  In production the scheme
 * persists via {@code Context.getUserService().setUserProperty(...)}; tests exercise the in-memory User only.
 */
public class MockTwoFactorAuthenticationScheme extends TwoFactorAuthenticationScheme {

    @Override
    protected void writeRememberMeToken(User user, String seriesId, String value) {
        user.setUserProperty(getRememberMeUserPropertyName(seriesId), value);
    }

    @Override
    protected void removeRememberMeToken(User user, String seriesId) {
        user.removeUserProperty(getRememberMeUserPropertyName(seriesId));
    }
}
