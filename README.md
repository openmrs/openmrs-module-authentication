# OpenMRS MFA (Multi-factor authentication) Module

## Description
This module provides support for enabling 2FA (two-factor authentication) and/or MFA (multi-factor authentication) into the OpenMRS login process.  It is intended to be configurable, to enable MFA to be enabled and/or required on a per-system and per-user basis, and to support various pluggable methods of MFA

## Configuration in mfa.properties

The operation of this module is fully configured based on a properties file in the application data directory named ```mfa.properties```.  This properties file supports the following settings:

#### configuration.cacheEnabled ####

**Default value**:  true

This controls whether configuration properties should be cached at startup or read from the mfa.properties file each time they are accessed.  By default, properties are cached in order to ensure performance is not adversely impacted.  However, this value is particularly helpful to set to "false" when developing and testing new features, in order to more rapidly test and troubleshoot configuration settings without the need to constantly restart OpenMRS to do so.

#### filter.enabled ####

**Default value**:  false

This determines whether the Authentication Filter is enabled, which will redirect users to authenticate if they have not already done so.  The default value is false, to ensure that simply installing this module does not impact existing systems.  Setting this value to true should be done in coordination with the ```filter.unauthenticatedUrls``` and ```filter.loginUrl``` configuration properties.

#### filter.unauthenticatedUrls ####

**Default value**:  none

If ```filter.enabled = true```, then this is a comma-delimited list of URL patterns that should be served without redirect to the configured login page.  This follows the ANT pattern-matching system.  One difference, for ease of configuration, is that any pattern that starts with "\*" is assumed to be an "ends with" pattern match, and will match on any url that ends with the specified pattern.  It essentially turns it into an ANT "/**/*..." match, meaning that any url that ends with the given pattern will be matched at any level of the hierarchy.

For example, what would otherwise require specifying patterns like this:
```/**/*.css,/**/*.gif,/**/*.jpg,/**/*.png```

Can instead be specified like this:
```*.css,*.gif,*.jpg,*.png```

As a starting point, if one wants to allow the 1.x (legacyui) login page to load successfully, along with all resources and the appropriate login servlets, the following configuration value can be used:

```filter.unauthenticatedUrls=/login.htm,/ms/legacyui/loginServlet,/csrfguard,*.js,*.css,*.gif,*.jpg,*.png```

#### filter.loginUrl ####

**Default value**:  /login.htm

If ```filter.enabled = true```, then if a url is requested, and the current user is not yet authenticated, and the url does not match any of the patterns configured in ```filter.unauthenticatedUrls```, then the filter will redirect to the url configured here.

### Sample mfa.properties file for filtering and redirecting to 1.x (legacyui) login page

```properties
configuration.cacheEnabled=false
filter.enabled=true
filter.unauthenticatedUrls=/login.htm,/ms/legacyui/loginServlet,/csrfguard,*.js,*.css,*.gif,*.jpg,*.png
```
