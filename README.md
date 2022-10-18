# OpenMRS Authentication Module

## Description
This module provides support for enhanced authentication features in OpenMRS and intends to fulfill the following goals:

* Harvest best practice authentication support from existing application frameworks
* Enable consistent backend authentication that is independent of UI or application (1.x, 2.x, 3.x etc)
* Support additional authentication factors beyond basic (username/password) authentication (2FA, MFA)
* Support fully configurable and extensible authentication, at both the application and user level
* Support additional authentication logging, to enable auditing and tracking of user access over time

## Configuration

The operation of this module is fully configured using OpenMRS runtime properties.  All properties are prefixed with `authentication.`

### authentication.scheme ###

**Default value**: Will default back to the core UsernamePasswordAuthenticationScheme

This property allows implementations to specify which the authentication scheme to use at runtime.  If not specified, then the module will default to the core UsernamePasswordAuthenticationScheme.  This property should reference one of the {schemeId} values that identify a particular configured scheme.

### authentication.settings.cached ###

**Default value**:  true

This controls whether configuration properties should be cached at startup to optimize performance, or whether they should not be cached to enable quick testing of runtime changes.  Typically, all production instances should leave this at the default value of true, but this may be helpful during development and initial testing phases to more rapidly test and troubleshoot configuration settings without the need for continuous server restarts.

#### authentication.whiteList ####

**Default value**:  none

If the configured `authentication.scheme` implements `WebAuthenticationScheme`, then this is a comma-delimited list of URL patterns that should be served without requiring a redirect to the configured challenge page if the current user is not authenticated.  The main purpose of this is to enable login pages, along with images and other resources, to be served without redirection for authentication.  The expected URL patterns follow the ANT pattern-matching system.  One difference, for ease of configuration, is that any pattern that starts with "\*" is assumed to be an "ends with" pattern match, and will match on any url that ends with the specified pattern.  It essentially turns it into an ANT "/**/*..." match, meaning that any url that ends with the given pattern will be matched at any level of the hierarchy.

For example, what would otherwise require specifying patterns like this:
```/**/*.css,/**/*.gif,/**/*.jpg,/**/*.png```

Can instead be specified like this:
```*.css,*.gif,*.jpg,*.png```

As a starting point, if one wants to allow the 1.x (legacyui) login page to load successfully, along with all resources and the appropriate login servlets, the following configuration value can be used:

```authentication.whiteList=/login.htm,/ms/legacyui/loginServlet,/csrfguard,*.js,*.css,*.gif,*.jpg,*.png```

### Authentication Schemes ###

All custom authentication schemes are identified with a `schemeId`.  This `schemeId` can be anything, but is typically concise, descriptive, and must be unique.  To configure a new authentication scheme with a given `schemeId`, you must include the following property in your configuration:

```properties
authentication.scheme.{schemeId}.type=fully.specified.name.of.authentication.scheme.class
```

If a given `AuthenticationScheme` implements `ConfigurableAuthenticationScheme`, then one can also specify the properties to configure it with as follows:

```properties
authentication.scheme.{schemeId}.config.{property1}={value1}
authentication.scheme.{schemeId}.config.{property2}={value2}
```

For example, to configure a new instance of the BasicWebAuthenticationScheme that is included in this module:

```properties
authentication.scheme.basic.type=org.openmrs.module.authentication.web.scheme.BasicWebAuthenticationScheme
authentication.scheme.basic.config.loginPage=/module/authentication/basic.htm
```

* This indicates that the unique `schemeId` of this `AuthenticationScheme` is `basic`
* This indicates that the type is a `BasicWebAuthenticationScheme`
* This indicates the properties that are used to configure the instance.
* One can specify 0-N configuration properties.  These properties are made available to the `ConfigurableAuthenticationScheme` without the prefix
  * In the example above, the `BasicAuthenticationScheme` would be given a property named `loginPage` with a value of `/module/authentication/basic.htm`


### Examples

### Legacy UI (1.x) login page

```properties
authentication.scheme=basic
authentication.whiteList=/index.htm,/csrfguard,/**/*.js,/**/*.css,/**/*.gif,/**/*.jpg,/**/*.png,/**/*.ico

authentication.scheme.basic.type=org.openmrs.module.authentication.web.scheme.BasicWebAuthenticationScheme
authentication.scheme.basic.config.loginPage=/index.htm
authentication.scheme.basic.config.usernameParam=uname
authentication.scheme.basic.config.passwordParam=pw
```

### Two-factor authentication example

```properties
authentication.scheme=mfa
authentication.whiteList=/**/authentication/basic.htm,/**/authentication/secret.htm,/csrfguard,/**/*.js,/**/*.css,/**/*.gif,/**/*.jpg,/**/*.png,/**/*.ico

authentication.scheme.mfa.type=org.openmrs.module.authentication.web.scheme.TwoFactorAuthenticationScheme
authentication.scheme.mfa.config.primaryOptions=basic
authentication.scheme.mfa.config.secondaryOptions=secret

authentication.scheme.basic.type=org.openmrs.module.authentication.web.scheme.BasicWebAuthenticationScheme
authentication.scheme.basic.config.loginPage=/module/authentication/basic.htm

authentication.scheme.secret.type=org.openmrs.module.authentication.web.scheme.SecretQuestionAuthenticationScheme
authentication.scheme.secret.config.loginPage=/module/authentication/secret.htm
```

## Background

### Core authentication

#### Authentication model

* Authenticated:  interface that represents a successful Authentication result, with access to authenticated User
* BasicAuthenticated:  Authenticated implementation that contains a User
* Credentials: interface representing data that can be checked to return an Authenticated, with access to clientName
* UsernamePasswordCredentials:  implementation of Credentials that contains username and password
* AuthenticationScheme:  interface for checking a Credentials and returning an Authenticated
* DaoAuthenticationScheme:  abstract AuthenticationScheme that provides direct access to the ContextDAO
* UsernamePasswordAuthenticationScheme: implementation of DaoAuthenticationScheme that expects UsernamePasswordCredentials and calls ContextDAO.authenticate

#### Context:

* Context bean defined in Spring application context has a defined init-method of setAuthenticationScheme
  * this will use a new UsernamePasswordAuthenticationScheme() by default
  * if Context.getServiceContext().getApplicationContext().getBean(AuthenticationScheme.class) is successful, it will use the result of this
* authenticate(username, password) - Deprecated, always uses new UsernamePasswordCredentials
* authenticate(Credentials)
  * if Daemon thread, return new BasicAuthenticated(daemon)
  * else if credentials != null, return UserContext.authenticate(credentials)
* logout()
  * UserContext.logout()
  * setUserContext(new UserContext(getAuthenticationScheme))
* getUserContext(), setUserContext(UserContext), clearUserContext()
  * Manipulates a ThreadLocal userContextHolder, which maintains a separate UserContext per Thread

#### UserContext

* properties
  * user (authenticated user)
  * proxies (List<String> of proxy privileges)
  * locale (user locale)
  * authenticatedRole (cached role given to all authenticated users)
  * anonymousRole (cached role given to all authenticated users)
  * locationId (users defined location)
  * authenticationScheme (the authentication scheme for this user) - set by constructor
* methods
  * authenticate(Credentials) 
    * sets user, locationId from users property OpenmrsConstants.USER_PROPERTY_DEFAULT_LOCATION
    * notifies UserSessionListener components of login success or login fail
    * throws ContextAuthenticationException if login fails
  * refreshAuthenticatedUser()
    * reloads user, locationId from service based on userId on existing user (refresh from DB)
  * becomeUser(String)
    * only allowed if Context.getAuthenticatedUser().isSuperUser()
    * gets the user Context.getUserService().getUserByUsername(systemId), and hydrates roles, properties, privileges
    * sets user, locationId from users property OpenmrsConstants.USER_PROPERTY_DEFAULT_LOCATION
    * service-only: set the Context locale to the user's USER_PROPERTY_DEFAULT_LOCALE or LocaleUtility.getDefaultLocale() if not defined
  * getAuthenticatedUser() -> returns user
  * isAuthenticated -> returns user != null
  * setLocale() -> sets locale
  * getLocale() -> returns locale or if null LocaleUtility.getDefaultLocale()
  * logout()
    * sets user = null
    * notifies UserSessionListener components of logout success
  * addProxyPrivilege(String)/removeProxyPrivilege(String)
  * getAllRoles() -> returns all roles assigned to the user, plus anonymous, plus authenticated
  * hasPrivilege() -> if has privilege, or has proxy privilege, returns true.  Notifies PrivilegeListener components of privilege check and result. 
  * other property accessors

#### ContextDAO / HibernateContextDAO

* authenticate(login, password)
  * Find User match by username or systemid that matches "login"
  * If no user was found, or password was not supplied, throw ContextAuthenticationException
  * If user is locked out, do not continue
    * Get user property OpenmrsConstants.USER_PROPERTY_LOCKOUT_TIMESTAMP
    * If this is found, and it is within 5 minutes (300000 ms.), throw ContextAuthentiationException, and set this to System.currentTimeMillis()
    * If this is found, but after 5 minutes, remove this and set property OpenmrsConstants.USER_PROPERTY_LOGIN_ATTEMPTS = 0
    * Get password and salt for User, and check if (passwordOnRecord != null && Security.hashMatches(passwordOnRecord, password + saltOnRecord))
    * If passes:
      * Hydrate user (roles, properties, privileges)
      * remove USER_PROPERTY_LOCKOUT_TIMESTAMP and set property OpenmrsConstants.USER_PROPERTY_LOGIN_ATTEMPTS = 0
      * return this user
    * If fails:
      * Get total login attempts for user (user property USER_PROPERTY_LOGIN_ATTEMPTS) and increment by 1
      * Compare against max allowed login attempts (GP OpenmrsConstants.GP_ALLOWED_FAILED_LOGINS_BEFORE_LOCKOUT, default 7)
      * If attempts > max allowed attempts, set User property USER_PROPERTY_LOCKOUT_TIMESTAMP, else set user property USER_PROPERTY_LOGIN_ATTEMPTS, save
      * throw ContextAuthenticationException

#### UserService...HibernateUserDAO

* getLoginCredentialByActivationKey(String)
  * Find LoginCredential where activationKey starts with Security.encodeString(activationKey)
  * Get the result, compare loginCredential.getActivationKey().split(":")[0] to activation key
  * If it matches, return the LoginCredential

* setUserActivationKey(LoginCredential) - saves this to DB

* getUserByActivationKey(String activationKey) - service-layer only
  * Calls getLoginCredentialByActivationKey(String) to get LoginCredential matching
  * Checks expiry - System.currentTimeMillis() <= Long.parseLong(activationKey.split(:)[1])
  * If not expired, returns User for the LoginCredential

* setUserActivationKey(User user)
  * keyDuration = default 10 minutes, settable via GP in millis - GP_PASSWORD_RESET_VALIDTIME, as long as this is between 1 minute and 12 hours
  * expiryTime = System.currentTimeMillis() + keyDuration
  * activationKey = Security.encodeString(RandomStringUtils.randomAlphanumeric(20)) + ":" + expiryTime
  * persists this activation key to the User LoginCredentials
  * sends an email to the user at their user.getEmail(), with contents defined by message properties and reset url defined by GP_PASSWORD_RESET_URL

* changePasswordUsingActivationKey(String activationKey, String newPassword)
  * Gets the User by getUserByActivationKey(activationKey)
  * If this user cannot be found, throw InvalidActivationKeyException
  * Call updatePassword(user, newPassword);

* updateUserPassword(String newHashedPassword, String salt, Integer changedBy, Date dateChanged, Integer userIdToChange)
  * Gets the LoginCredential for the userIdToChange, updates properties, saves to DB
  * Resets the OpenmrsConstants.USER_PROPERTY_LOCKOUT_TIMESTAMP, OpenmrsConstants.USER_PROPERTY_LOGIN_ATTEMPTS properties

* changePassword(User, String)
  * Only uses the passed in user if there is no authenticated user, otherwise uses authenticated user
  * Generates a salt - Security.getRandomToken()
  * Hashes the password - Security.encodeString(pw + salt)
  * Updates using updateUserPassword above

* updatePassword(User, String) - Service-layer only
  * OpenmrsUtil.validatePassword(user.getUsername(), newPassword, user.getSystemId())
  * changePassword(User, String)

* changePassword(User u, String oldPw, String newPw) (Service-layer only)
  * Validate user, privileges, check oldPw correct, check oldPw != newPw, calls updatePassword above

* changePasswordUsingSecretAnswer(String secretAnswer, String pw)
  * Gets authenticated user, and checks if secret answer matches isSecretAnswer(user, secretAnswer).  if so, updatePassword above

* changeHashedPassword(User u, String hashedPassword, String salt)
  * calls updateUserPassword above, changing the password of the passed in user

* changePassword(String pw, String pw2)
  * Gets current authenticated user
  * Proceeds only if existing password matches pw credentials.checkPassword(pw)
  * Generates a new salt - Security.getRandomToken()
  * Hashes the new password - Security.encodeString(pw2 + salt)
  * Calls updateUserPassword for authenticated user if existing  with new salt and new hashed password of pw2

* getSecretQuestion(User user) service-layer only
  * Get LoginCredential for user and return the secret question

* changeQuestionAnswer(User u, String question, String answer)
  * Gets the LoginCredential for the provided user (u)
  * Sets the secret question directly
  * Hashes and sets the secret answer with current salt Security.encodeString(answer.toLowerCase() + credentials.getSalt())

* changeQuestionAnswer(String pw, String question, String answer)
  * Gets the LoginCredential for the current authenticated user
  * Proceeds only if existing password matches pw credentials.checkPassword(pw)
  * Calls changeQuestionAnswer(u, question, answer)

* isSecretAnswer(User u, String answer)
  * Gets the LoginCredential for the given user
  * Encodes the provided answer with the salt from the LoginCredential - Security.encodeString(answer.toLowerCase() + credentials.getSalt())
  * Compares this to the value in the LoginCredential

#### LoginCredential

* userId
* hashedPassword
* salt
* secretQuestion
* secretAnswer
* activationKey
* boolean checkPassword(String pw) - Security.hashMatches(getHashedPassword(), pw + getSalt())

#### WebConstants

* Request Attributes
  * "__INIT_REQ_UNIQUE_ID__"
* SessionAttributes
  * "__openmrs_context"
  * "__openmrs_user_context";
  * "__openmrs_client_ip";
  * "__openmrs_login_redirect";
  * "referer_url"
* Cookies
  * "__openmrs_language"
* Global Properties
  * "security.loginAttemptsAllowedPerIP"
* Servlet Context
  * CURRENT_USERS - usernames of the logged-in users are stored in this map (session id, username) in the ServletContext under this key

#### OpenmrsFilter

* gets or creates a session from the request
* sets session attribute "username" = "-anonymous user-"
* gets user context from session attribute (WebConstants.OPENMRS_USER_CONTEXT_HTTPSESSION_ATTR):
  * if found, and there is a non-null user in it, sets session attribute "username" to user.getUsername()
  * if not found, creates new UserContext(Context.getAuthenticationScheme()) as sets as session attribute
* sets session attribute "locale" = userContext.getLocale()
* if request.getRequestURI().endsWith("csrfguard"), ensure this is not cached by setting response headers:
  * response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate"); // HTTP 1.1.
  * response.setHeader("Pragma", "no-cache"); // HTTP 1.0.
  * response.setHeader("Expires", "0"); // Proxies.
* ensure thread has userContext set and OpenmrsClassloader set for further request processing:
  Context.setUserContext(userContext);
  * Thread.currentThread().setContextClassLoader(OpenmrsClassLoader.getInstance());

#### CsrfGuardFilter

* org.owasp.csrfguard.CsrfGuardFilter
* Added after OpenmrsFilter

#### Module filters

* Filters defined in modules run after the CsrfGuardFilter, in order in which they are added through modules

### REST authentication (webservices.rest)

#### AuthorizationFilter

* if request.getRemoteAddr() does not match those defined in ALLOWED_IPS_GLOBAL_PROPERTY_NAME
  * response.sendError(HttpServletResponse.SC_FORBIDDEN, "IP address '" + request.getRemoteAddr() + "' is not authorized");

* if request is not an HttpServletRequest, allow
* if request.getRequestedSessionId() != null && !request.isRequestedSessionIdValid()
  * response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Session timed out")
* if Context.isAuthenticated(), allow
* if !Context.isAuthenticated()
  * basicAuth = httpRequest.getHeader("Authorization")
  * check that header is in format "Basic ${base64encode(username + ":" + password)}"
  * if basicAuth.startsWith("Basic"), basicAuth = basicAuth.substring(6);
  * if basicAuth is blank, response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid credentials provided")
  * else, decode it:  String decoded = new String(Base64.decodeBase64(basicAuth), Charset.forName("UTF-8"))
  * if decoded is blank or does not contain ":", response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid credentials provided")
  * split on ":" to get username and password, and call Context.authenticate(username, password)
* Continue on, if the user is not authenticated, relies on the API to throw exceptions if an unauthenticated user tries to do something they are not allowed to do.

### FHIR2 authentication (fhir2)

#### RequireAuthorizationInterceptor

* Allow if request.getRequestURI().contains("/.well-known") || request.getRequestURI().endsWith("/metadata")
* Allow if User.isAuthenticated()
* Else -> response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Not authenticated")

#### AuthenticationFilter

* If request in an HttpServletRequest
  * If request.getRequestedSessionId() != null && !httpRequest.isRequestedSessionIdValid() -> Context.logout()
  * if !user.isAuthenticated()
    * if !(request.getRequestURI().contains("/.well-known") || Request.getRequestURI().endsWith("/metadata")
      * Try to authenticate using Authorization header "Basic ${base64encode(username + ":" + password)}"
        * String basicAuth = httpRequest.getHeader("Authorization")
        * if (!StringUtils.isBlank(basicAuth) && basicAuth.startsWith("Basic")), try to authenticate
          * basicAuth = basicAuth.substring(6);
          * String decoded = new String(Base64.decodeBase64(basicAuth), StandardCharsets.UTF_8); 
          * String[] userAndPass = decoded.split(":"); 
          * Context.authenticate(userAndPass[0], userAndPass[1]);
        * if exception
          * response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Not authenticated")
          * return
        * else if no basic auth header was found, do nothing (assume authentication will be handled or caught later)

### 1.x application authentication (legacyui)

Authentication in the 1.x framework is included in core up until 2.0, at which point this functionality is in the legacyui module.  The below is based on a review of legacyui authentication code.

#### LoginServlet:

* Gets request.getRemoteAddr():
  - Tracks total number of login attempts by IP in local variable, resets after IP authenticates successfully
  - If this > GP_ALLOWED_LOGIN_ATTEMPTS_PER_IP (default 100):
    - lockout further attemps from this IP for 5 minutes (300000 ms) (tracked in local variables)
    - set session attribute:  WebConstants.OPENMRS_ERROR_ATTR = "auth.login.tooManyAttempts"

* Get redirect url
  - if request has a parameter named "redirect", use it
  - else if request has a parameter "refererURL", use it
  - if this does not start with "/"
    - make sure this is in the right domain (check domain and port in request url matches redirect url)
    - remove the domain and port from the url
  - else, use context path
  - if redirect here is empty, to a login page, a page outside of the domain, or the initialsetup page,  use context path
  - if redirect is to a password change page, use context path

* Get the username and password.
  - Get request parameters "uname" nad "pw"
  - If username is empty:  throw new ContextAuthenticationException("Unable to authenticate with an empty username");

* Try to authenticate
  - If successful
    - regenerate http session
      - get all attributes off of the current session
      - call invalidate() on current session
      - get new session - request.getSession(true)
      - copy all attributes onto the new session
    - remove ipAddress from loginAttemptsByIp tracker
    - set session attribute:  "loginAttempts" = 0
    - get the users's default locale from their user properties, and if valid, set in a cookie
      - user property: OpenmrsConstants.USER_PROPERTY_DEFAULT_LOCALE
      - convert to Locale:  WebUtil.normalizeLocale(localeString)
      - set cookie if locale is not null: new OpenmrsCookieLocaleResolver().setLocale(request, response, locale)
    - check if users is supposed to change password UserProperties.isSupposedToChangePassword())
      - If so, set session attribute WebConstants.OPENMRS_MSG_ATTR = "User.password.change"
      - set redirect url to "/changePassword.form"
    - if Context.getLocale() == null, set this to LocaleUtility.getDefaultLocale()
    - Maintains a list of CurrentUsers - CurrentUsers.addUser(httpSession, user);
    - response.sendRedirect(redirect url)
    - set session attribute:  WebConstants.OPENMRS_CLIENT_IP_HTTPSESSION_ATTR = request.getLocalAddr()
    - remove session attribute:  WebConstants.OPENMRS_LOGIN_REDIRECT_HTTPSESSION_ATTR
  - If unsuccessful
    - set session attribute:  WebConstants.OPENMRS_ERROR_ATTR = "auth.password.invalid"
  - if locked out or unsuccessful:
    - set session attribute WebConstants.OPENMRS_LOGIN_REDIRECT_HTTPSESSION_ATTR = redirect url
    - increment the loginAttemptsByIP by 1
    - redirect to /login.htm

#### LogoutServlet:

* Context.logout();
* session.invalidate();
* redirect to /index.htm

#### Login page (login.jsp, portlets/login.jsp, LoginController):

* set "redirect" pageContext attribute from WebConstants.OPENMRS_LOGIN_REDIRECT_HTTPSESSION_ATTR, and clear this from session
* allow login with username/password, posting to LoginServlet, and link to /forgotPassword.form
* set "redirect" form parameter from one passed into login page as parameter if present, or one pulled from pageContext attribute above, or ""
* set "refererURL" form parameter to "referer" request header
* display any error messages
* handles a use case where the reason the user is here is due to a failed privilege check when logged in (eg. see RequreTag)
  - gets and removes WebConstants.DENIED_PAGE, WebConstants.REQUIRED_PRIVILEGES, WebConstants.UNCAUGHT_EXCEPTION_MESSAGE, WebConstants.REFERER_URL from session
  - sets an appropriate message to display based on the above session attributes
  - sets the referer url for the login page, if found in the above session attributes
  - sets the redirect_url for the login page, if found in the request

### RequireTag

* Most 1.x pages have checks like this at the top:  <openmrs:require privilege="View Patients" otherwise="/login.htm" redirect="/patientDashboard.form" />
* If no authenticated user:
  * set session attribute: WebConstants.OPENMRS_MSG_ATTR = "require.login"
  * errorOccurred = true
* If authenticated user doesn't have privileges:
  * set session attribute: WebConstants.INSUFFICIENT_PRIVILEGES = true
  * set session attribute: WebConstants.REQUIRED_PRIVILEGES = the missing privileges
  * set session attribute: WebConstants.REFERER_URL = request.getHeader("Referer")
  * set session attribute: WebConstants.DENIED_PAGE = "redirect" parameter if passed into the tag, else referer above
  * errorOccurred = true
* If authenticated user has privilege, but is marked as needing to change password:
  * set session attribute: WebConstants.OPENMRS_ERROR_ATTR = "User.password.change"
  * redirect to request.getContextPath() + "/options.form#Change Login Info"
* If ip address of request does not match that of session:
  * Get stored session IP: WebConstants.OPENMRS_CLIENT_IP_HTTPSESSION_ATTR
  * Get request IP: request.getLocalAddr()
  * Consider "127.0.0.1" and "0.0.0.0" to be equal
  * If they do not match:
    * errorOccurred = true
    * If request IP address != "0.0.0.0", set session attribute: WebConstants.OPENMRS_ERROR_ATTR = "require.ip_addr"
* If errorOccurred = true above:
  * If redirect was specified in the tag, or set otherwise, set url = request.getContextPath() + redirect, else set url = request.getRequestURI()
  * if request.getQueryString() != null, set url = url + "?" + request.getQueryString()
  * set session attribute WebConstants.OPENMRS_LOGIN_REDIRECT_HTTPSESSION_ATTR = url
  * redirect to "otherwise" tag parameter (eg. login page)

#### Filters and Listeners (WebComponentRegistrar, RedirectAfterLoginFilter, ForcePasswordChangeFilter, SessionListener)

* RedirectAfterLoginFilter
  * For URL patterns "*.htm", "*.form", "*.list", "*.json", "*.field", "*.portlet", "*.page", "*.action"
  * if !Context.isAuthenticated()
    * if this is a GET request (request.getMethod()) and is not for the login page !request.getRequestURI().contains("login.")
      * get the session request.getSession(false), and if it is not null, and does not already contain attribute OPENMRS_LOGIN_REDIRECT_HTTPSESSION_ATTR
        * construct redirect = request.getRequestURI() + StringUtils.isNotBlank(request.getQueryString()) ? "?" + request.getQueryString() : ""
        * set session attribute OPENMRS_LOGIN_REDIRECT_HTTPSESSION_ATTR = redirect

* ForcePasswordChangeFilter
  * For URL patterns "/*"
  * changePasswordForm = "/admin/users/changePassword.form"
  * excludeURL = "changePasswordForm,logout,.js,.css,.gif,.jpg,.jpeg,.png"
  * If Context.isAuthenticated() and 
  * If new UserProperties(Context.getAuthenticatedUser().getUserProperties()).isSupposedToChangePassword() and
  * If request.getRequestURI() does not end with any of the excluded URLs
  * config.getServletContext().getRequestDispatcher(changePasswordForm).forward(request, response)

* SessionListener
  * When session is destroyed - CurrentUsers.removeSessionFromList(httpSessionEvent.getSession());

#### Profile Pages (optionsForm.jsp, OptionsFormController, changePasswordForm.jsp)

  - Set default user properties: 
    - OpenmrsConstants.USER_PROPERTY_DEFAULT_LOCATION = defaultLocation
    - OpenmrsConstants.USER_PROPERTY_DEFAULT_LOCALE = WebUtil.normalizeLocale(defaultLocale)
    - OpenmrsConstants.USER_PROPERTY_PROFICIENT_LOCALES = WebUtil.sanitizeLocales(proficientLocales)
    - OpenmrsConstants.USER_PROPERTY_SHOW_RETIRED = showRetiredMessage
    - OpenmrsConstants.USER_PROPERTY_SHOW_VERBOSE = verbose
  - Set login credentials:  username, personName, oldPassword, newPassword, confirmPassword, secretQuestionPassword, secretQuestionNew, secretAnswerNew, secretAnswerConfirm
    - Validates username doesn't exist: UserService.hasDuplicateUsername(user) - "error.username.taken"
    - Validates that oldPassword and newPassword are not empty ("error.password.incorrect", "error.password.weak")
    - Validates password does not match old password "error.password.different"
    - Validates newPassword matches confirmPassword "error.password.match"
    - OpenmrsUtil.validatePassword(user.getUsername(), password, String.valueOf(user.getUserId()))
    - If secretQuestionPassword is empty and secretQuestionNew is empty and secretQuestionNew != secretQuestionCopy -> "error.password.incorrect"
    - If secretQuestionPassword and secretAnswerNew is not empty "error.password.incorrect"
    - if secretAnswerNew != secretAnswerConfirm -> error.options.secretAnswer.match
    - if secretAnswerNew is empty -> error.options.secretAnswer.empty
    - if secretQuestionNew is empty -> error.options.secretQuestion.empty
    - If passes: 
      - UserService.changePassword(oldPassword, newPassword)
      - if secretQuestionPassword == oldPassword, set secretQuestionPassword = newPasswordPassword )
      - new UserProperties(user.getUserProperties()).setSupposedToChangePassword(false)
      - if secretQuestionPassword != null, UserService.changeQuestionAnswer(secretQuestionPassword, secretQuestionNew, secretAnswerNew)
  - Set notification properties:
    - Validates email: EmailValidator.getInstance().isValid(opts.getNotificationAddress())
    - OpenmrsConstants.USER_PROPERTY_NOTIFICATION = internalOnly,internal,internalProtected,""
    - OpenmrsConstants.USER_PROPERTY_NOTIFICATION_ADDRESS = notificationAddress
  - When saving update to user:
    - Sets username
    - email?
    - If new name, voids old name, adds new name, marks as preferred
    - Validates user
    - Saves user
    - PseudoStaticContentController.invalidateCachedResources(properties);
    - Context.refreshAuthenticatedUser();

#### User Administration Pages (userForm.jsp, UserFormController)

* Allows becoming a user - Context.becomeUser(user.getSystemId())
* Allows deleting a user - Context.getUserService().purgeUser(user)
* Allows retiring a user - Context.getUserService().retireUser(user, retireReason)
* Allows un-retiring a user - Context.getUserService().unretireUser(user)
* Allows forcing password change - new UserProperties(user.getUserProperties()).setSupposedToChangePassword(forcePassword)
* Allows setting secret question and answer - Context.getUserService().changeQuestionAnswer(user, secretQuestion, secretAnswer)
* Allows setting user attributes, properties, names, username, password, roles, provider (with validation)

#### Forgot password (forgotPasswordForm.jsp, ForgotPasswordFormController)

* Gets "uname" request parameter
* Gets ip address from request - request.getRemoteAddr()
* Tracks, in local variables, loginAttemptsByIP, lockoutDateByIP.  Allows 5 attempts before locking out for 5 minutes (300000 ms)
* If locked out, set session attribute WebConstants.OPENMRS_ERROR_ATTR = "auth.forgotPassword.tooManyAttempts", redirects back to form
* Increment loginAttemptsByIP++
* Get "secretAnswer" request parameter
  * If secretAnswer is empty:
    * If the user provided a valid username and a user was found:
      * If they have a secret question defined - Context.getUserService().getSecretQuestion(user)
        * set session attribute WebConstants.OPENMRS_MSG_ATTR = "auth.question.fill"
        * set request attribute "secretQuestion" = their secret question
        * Reset loginAttemptsByIP = 0
        * redirect to form
      * If they do not have a secret question defined, set session attribute WebConstants.OPENMRS_ERROR_ATTR = "auth.question.empty"
    * If no valid user was found:
      * set session attribute: WebConstants.OPENMRS_MSG_ATTR = "auth.question.fill"
      * set request attribute "secretQuestion" to getRandomFakeSecretQuestion(username)
  * If secretAnswer is not empty:
    * If the user provided a valid username and a user was found:
      * Get the user's secretQuestion: Context.getUserService().getSecretQuestion(user)
      * If they do not have a secret question defined, set session attribute WebConstants.OPENMRS_ERROR_ATTR = "auth.question.empty"
      * If they have a secret question defined, and Context.getUserService().isSecretAnswer(user, secretAnswer))
        * Generate a new random password (randomPassword)
          * minLength = OpenmrsConstants.GP_PASSWORD_MINIMUM_LENGTH or 8
          * RandomStringUtils.randomAlphabetic(1).toUpperCase() + RandomStringUtils.randomAlphanumeric(minLength) + RandomStringUtils.randomNumeric(1);
        * Set this as the user's password:  Context.getUserService().changePassword(user, randomPassword);
        * Set session attribute resetPassword = randomPassword
        * Set session attribute WebConstants.OPENMRS_MSG_ATTR = "auth.password.reset")
        * Authenticate the user with this password: Context.authenticate(username, randomPassword);
        * Set session attribute "loginAttempts" = 0
      * If they have a secrete question defined, and the answer provided is wrong:
        * set session attribute: WebConstants.OPENMRS_ERROR_ATTR = "auth.answer.invalid"
        * set session attribute: WebConstants.OPENMRS_MSG_ATTR = "auth.question.fill"
        * set session attribute: "secretQuestion" = secretQuestion
  * If no valid user was found:
    * set session attribute: WebConstants.OPENMRS_ERROR_ATTR = "auth.answer.invalid"
    * set session attribute: WebConstants.OPENMRS_MSG_ATTR = "auth.question.fill"
    * set request attribute "secretQuestion" to getRandomFakeSecretQuestion(username)
      * from list of questions: 
        * "What is your best friend's name?"
        * "What is your grandfather's home town?"
        * "What is your mother's maiden name?"
        * "What is your favorite band?"
        * "What is your first pet's name?"
        * "What is your brother's middle name?"
        * "Which city were you born in?"
      * choose randomly but consistently for a given username: questions.get(Math.abs(username.hashCode()) %= questions.size())

#### Authentication Failure Checking (authorizationHandlerInclude.jsp)

* Included in error pages (errorhandler.jsp, uncaughtException.jsp)
* If the exception leading to these error pages is a ContextAuthenticationException or APIAuthenticationException
* If Context.getAuthenticatedUser() != null
  * set session attribute: WebConstants.INSUFFICIENT_PRIVILEGES = true
  * set session attribute: WebConstants.UNCAUGHT_EXCEPTION_MESSAGE = exception.getMessage()
  * set session attribute: WebConstants.REFERER_URL = request.getHeader("Referer")
  * if request.getAttribute("javax.servlet.error.request_uri") is not blank:
    * set session attribute: WebConstants.DENIED_PAGE = this uri
    * set session attribute: WebConstants.OPENMRS_LOGIN_REDIRECT_HTTPSESSION_ATTR = this uri + (if request.getQueryString() ? "?" + request.getQueryString())
* redirect to login page: request.getContextPath() + "/login.htm"

### 2.x application authentication (openmrs-module-referenceapplication)

#### Login Page (LoginPageController, login.gsp)

* If user already logged in, forward to home page, else forward to login page
* Logic around ensuring a session location is set (checking and redirects in login page, also a RequireLoginLocationFilter)
* Logic to determine whether to use user's default location, or to show session locations picker on login page
* Form based login (collect parameters named `username` and `password`), plus lots of logic around session location selection.
* On login form submission:
  * redirectUrl = first of "redirectUrl" in request, _REFERENCE_APPLICATION_REDIRECT_URL_ from session, "referer" where referer logic is:
    * if session attribute "manual-logout" != true, then request.getHeader("Referer")
    * if session attribute "manual-logout" = true, return "", add cookie to response: _REFERENCE_APPLICATION_LAST_USER_ to null, maxAge=0, httpOnly=true
    * set session attribute "manual-logout" to null
  * if (!Context.isAuthenticated)
    * Context.authentiate(username, password)
    * set client timezone properties and session location stuff, redirecting to pages to get location as needed
    * if sessionLocation != null and supports login
      * set cookie 
      * response.addCookie(new Cookie(COOKIE_NAME_LAST_SESSION_LOCATION, sessionLocationId.toString()).setHttpOnly(true)))
      * CurrentUsers.addUser(request.getSession(), Context.getAuthenticatedUser());
      * set default locale:
        * get default locale for user, and if not null:
          * Context.getUserContext().setLocale(userLocale)
          * response.setLocale(userLocale)
          * new CookieLocaleResolver().setDefaultLocale(userLocale)
      * redirect:
        * if redirectUrl provided, use it unless:
          * is not within openmrs (see LoginPageController for details)
          * it contains "login." and isSameUser(request, username)
        * otherwise redirect to home
