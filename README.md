# OpenMRS MFA (Multi-factor authentication) Module

## Description
This module provides support for enabling 2FA (two-factor authentication) and/or MFA (multi-factor authentication) into the OpenMRS login process.  It is intended to be configurable, to enable MFA to be enabled and/or required on a per-system and per-user basis, and to support various pluggable methods of MFA

## Configuration in mfa.properties

The operation of this module is fully configured based on a properties file in the application data directory named ```mfa.properties```.  This properties file supports the following settings:

### Overall Settings ###

#### mfa.enabled ####

**Default value**:  false

This determines whether the Authentication Filter is enabled, which will redirect users to authenticate if they have not already done so.  The default value is false, to ensure that simply installing this module does not impact existing systems.  Setting this value to true should be done once other properties are configured to enable a functional login workflow.

#### mfa.disableConfigurationCache ####

**Default value**:  false

This controls whether configuration properties should be cached re-read from the mfa.properties file for each request.  By default, properties are cached in order to ensure performance is not adversely impacted.  However, this value is particularly helpful to set to "true" when developing and testing new features, in order to more rapidly test and troubleshoot configuration settings without the need to constantly restart OpenMRS to do so.

#### mfa.unauthenticatedUrls ####

**Default value**:  none

If ```mfa.enabled = true```, then this is a comma-delimited list of URL patterns that should be served without redirect to the configured login page.  This follows the ANT pattern-matching system.  One difference, for ease of configuration, is that any pattern that starts with "\*" is assumed to be an "ends with" pattern match, and will match on any url that ends with the specified pattern.  It essentially turns it into an ANT "/**/*..." match, meaning that any url that ends with the given pattern will be matched at any level of the hierarchy.

For example, what would otherwise require specifying patterns like this:
```/**/*.css,/**/*.gif,/**/*.jpg,/**/*.png```

Can instead be specified like this:
```*.css,*.gif,*.jpg,*.png```

As a starting point, if one wants to allow the 1.x (legacyui) login page to load successfully, along with all resources and the appropriate login servlets, the following configuration value can be used:

```mfa.unauthenticatedUrls=/login.htm,/ms/legacyui/loginServlet,/csrfguard,*.js,*.css,*.gif,*.jpg,*.png```


### Authenticators ###

For each Authenticator configuration supported by the system, a series of properties should be added that identify the type of this authenticator, and it's configuration properties.

#### authenticator.<name> and authenticator.<name>.config.<propertyName> ###

For example, to configure the default BasicWebAuthenticator that is included in this module:

```properties
authenticator.basic.type=org.openmrs.module.mfa.web.BasicWebAuthenticator
authenticator.basic.config.loginPage=/module/mfa/basic.htm
```

* This indicates that the unique `name` of this Authenticator instance is `basic`
* This indicates that the type is a `BasicWebAuthenticator`
* This indicates the properties that are used to configure the instance.
* One can specify 0-N configuration properties.  All are prefixed by `authenticator.<name>.config.<propertyName>`
* The `BasicWebAuthenticator` in the above example supports a single parameter named `loginPage`

#### authenticators.primary ####

**Default value**:  none

This is the `name` of the authenticator that should be used as the primary authenticator for the system.  To configure the above example `BasicWebAuthenticator` instance as the primary authenticator, you would specify:

`authenticators.primary = basic`

#### authenticators.secondary ####

**Default value**:  none

This is a comma-separated list of authenticator `name` that should be made available for use in secondary authentication.

### Sample mfa.properties file for filtering and redirecting to 1.x (legacyui) login page

```properties
configuration.cacheEnabled=false
filter.enabled=true
filter.unauthenticatedUrls=/login.htm,/ms/legacyui/loginServlet,/csrfguard,*.js,*.css,*.gif,*.jpg,*.png
```

### Sample mfa.properties file that can be used to demonstrate multi-factor authentication

```properties
mfa.enabled=true
mfa.disableConfigurationCache=true
mfa.unauthenticatedUrls=/**/mfa/basic.htm,/**/mfa/token.htm,/csrfguard,/**/*.js,/**/*.css,/**/*.gif,/**/*.jpg,/**/*.png,/**/*.ico

authenticators.primary=basic
authenticators.secondary=dummy

authenticator.basic.type=org.openmrs.module.mfa.web.BasicWebAuthenticator
authenticator.basic.config.loginPage=/module/mfa/basic.htm

authenticator.dummy.type=org.openmrs.module.mfa.web.TokenWebAuthenticator
authenticator.dummy.config.loginPage=/module/mfa/token.htm
```