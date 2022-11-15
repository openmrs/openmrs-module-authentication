# OpenMRS Authentication Module

## Description
This module provides support for enhanced authentication features in OpenMRS and intends to fulfill the following goals:

* Harvest best practice authentication support from existing application frameworks
* Enable consistent backend authentication that is independent of UI or application (1.x, 2.x, 3.x etc)
* Support additional authentication factors beyond basic (username/password) authentication (2FA, MFA)
* Support fully configurable and extensible authentication, at both the application and user level
* Support additional authentication logging, to enable auditing and tracking of user access over time

### Key terms

* Authenticated:  interface that represents a successful Authentication result, with access to authenticated User
* BasicAuthenticated:  Authenticated implementation that contains a User
* Credentials: interface representing data that can be checked to return an Authenticated, with access to clientName
* UsernamePasswordCredentials:  implementation of Credentials that contains username and password
* AuthenticationScheme:  interface for checking a Credentials and returning an Authenticated
* DaoAuthenticationScheme:  abstract AuthenticationScheme that provides direct access to the ContextDAO
* UsernamePasswordAuthenticationScheme: implementation of DaoAuthenticationScheme authenticates using UsernamePasswordCredentials

## Configuration

This module is intended to be fully configurable and extensible.  Modules are expected to depend upon this module and introduce their own custom authentication schemes that would work within the authentication framework.  Everything that supports configuration parameters is expected to support these at runtime via direct configuration or via OpenMRS runtime properties.

All configuration described in this README can be done as follows:

* By adding additional properties to the runtime properties file.
* By direct configuration via static method:  `AuthenticationConfig.setProperty(property, value);`
* All properties should be prefixed with `authentication.`

## Features

### Default Authentication Scheme

OpenMRS supports overriding the default `UsernamePasswordAuthenticationScheme` with a custom authentication scheme.  It does this at startup by inspecting the Spring context for any beans that implement `AuthenticationScheme` to use in place of this default .

This module registers a custom `DelegatingAuthenticationScheme`.  This `DelegatingAuthenticationScheme` is just a proxy, which delegates to another `AuthenticationScheme` that is configured at runtime. If no such configuration is found (eg. the module is installed but not configured), then it simply delegates back to the core `UsernamePasswordAuthenticationScheme`.  However, if configuration is found, then it will attempt to instantiate and use the defined scheme.

Configuring the default scheme is a matter of setting the `authentication.scheme` configuration property to the `schemeId` of a configured scheme (see sections below)

```properties
authentication.scheme=mySchemeId
```

### Configuring available Authentication Schemes

Although only one `AuthenticationScheme` can be set for the system as the one used to authenticate a User, an `AuthenticationScheme` itself can delegate to other `AuthenticationScheme` instances as appropriate.  For example a `TwoFactorAuthenticationScheme` may delegate to two separate `AuthenticationScheme` instances to perform each factor of authentication.  Each `AuthenticationScheme` that the system could utilize is configured at runtime by associating a unique `schemeId` with the class name of the `AuthenticationScheme` that should be instantiated.  This `schemeId` can be anything, but is typically concise, descriptive, and must be unique.  It should not contain white space.

```properties
authentication.scheme.mySchemeId.type=org.openmrs.module.mymodule.MyCustomAuthenticationScheme
```

If this `AuthenticationScheme` implements `ConfigurableAuthenticationScheme`, then the instantiated scheme is also configured with the configured property values. 

```properties
authentication.scheme.mySchemeId.config.propertyOne=valueOne
authentication.scheme.mySchemeId.config.propertyTwo=valueTwo
```

### Web Authentication Schemes

In OpenMRS, authentication is done in the API layer, thus the core authentication API is not aware of a web context.  However, nearly all clients of OpenMRS operate in a web context and an authentication workflow involves requesting and receiving credentials from a client.  Thus, in this module, all of the `AuthenticationScheme` implementations that can be used extend a base `WebAuthenticationScheme`, which is a type of `ConfigurableAuthenticationScheme`

The way `WebAuthenticationScheme` instances are utilized are via the included `AuthenticationFilter` that is registered with OpenMRS to check all requests into the web application.  This filter checks whether a user is unauthenticated and whether the `AuthenticationScheme` is a `WebAuthenticationScheme`.  If both are true, then this filter delegates to the `WebAuthenticationScheme` to check the request for credentials and to validate and authenticate with these credentials if found, to redirect the user to an appropriate page to collect credentials if not found, and to execute any additional logic prior to authentication or after authentication success or failure.  A given `WebAuthenticationScheme` is also aware of whether it requires additional configuration to be enabled for a particular user, and can redirect to an appropriate configuration page if so.

Once authentication is successful via the `AuthenticationFilter`, the HTTP Session is invalidated and regenerated to guard against Session Fixation attacks.

Because `WebAuthenticationScheme` implementations require users to be able to interact with certain login pages and embedded resources (images, etc), the `AuthenticationFilter` provides a mechanism to define a white-list of URL patterns that should be allowed without forcing a redirect to authenticate.  This is expected to be a comma-delimited list of URL patterns that follow the ANT pattern-matching system.  One difference, for ease of configuration, is that any pattern that starts with "\*" is assumed to be an "ends with" pattern match, and will match on any url that ends with the specified pattern.  It essentially turns it into an ANT "/**/*..." match, meaning that any url that ends with the given pattern will be matched at any level of the hierarchy.

```properties
authentication.whiteList=/login.htm,/ms/legacyui/loginServlet,/csrfguard,*.js,*.css,*.gif,*.jpg,*.png
```

To determine whether a particular url is leading to redirection, one can enable DEBUG logging on `org.openmrs.module.authentication.web.AuthenticationFilter` and look for a message in the logs indicating `Authentication required: [method] [uri]`

### Provided Authentication Schemes

Implementations, in dependent modules, can define their own `WebAuthenticationScheme` instances to best meet their needs and workflows.  There are several `WebAuthenticationScheme` types built into this module that will meet some of the most common needs and also provide examples to follow for customization.

#### BasicWebAuthenticationScheme

This essentially replicates (and delegates to) the core `UsernamePasswordAuthenticationScheme` but adds the benefits of being a `WebAuthenticationScheme`.

To configure a new instance, you would first add the following to your configuration to register a scheme of this type with a particular scheme id.  You would then customize the scheme with any configurable parameter values.  The below shows an example of this with a schemeId of `basic` and all available configuration parameters listed with their defaults.

```properties
authentication.scheme.basic.type=org.openmrs.module.authentication.web.BasicWebAuthenticationScheme
authentication.scheme.basic.config.loginPage=/login.htm
authentication.scheme.basic.config.usernameParam=username
authentication.scheme.basic.config.passwordParam=password
```

In addition, the `BasicWebAuthenticationScheme` also supports authenticating via an Authorization header, as supported by the `webservices.rest` and `fhir2` modules.  Instead of posting username and password from a login page, one can instead add a header to any request with name `Authorization` and value in the format: `Basic ${base64encode(username + ":" + password)}` 

#### SecretQuestionAuthenticationScheme

The `SecretQuestionAuthenticationScheme` is intended to be used as a secondary authentication factor, and allows a candidate user to be authenticated using their configured secret question and answer.

To configure a new instance, you would first add the following to your configuration to register a scheme of this type with a particular scheme id.  You would then customize the scheme with any configurable parameter values.  The below shows an example of this with a schemeId of `secret` and all available configuration parameters listed with their defaults.

```properties
authentication.scheme.secret.type=org.openmrs.module.authentication.web.SecretQuestionAuthenticationScheme
authentication.scheme.secret.config.loginPage=/loginWithSecret.htm
authentication.scheme.secret.config.questionParam=question
authentication.scheme.secret.config.answerParam=answer
```

#### TwoFactorAuthenticationScheme

The `TwoFactorAuthenticationScheme` is intended to be used as a default authentication scheme, and allows a candidate user to be authenticated using either just a primary authentication scheme or both a primary and secondary authentication scheme, if configured.

To configure a new instance, you would first add the following to your configuration to register a scheme of this type with a particular scheme id.  You would then customize the scheme with any configurable parameter values.  The below shows an example of this with a schemeId of `2fa` and all available configuration parameters listed with dummy values that assume 4 other configuration schemes are configured with schemeIds of `basic`, `secret`, `anotherOption` and `yetAnotherOption`.

```properties
authentication.scheme.secret.type=org.openmrs.module.authentication.web.TwoFactorAuthenticationScheme
authentication.scheme.secret.config.primaryOptions=basic
authentication.scheme.secret.config.secondaryOptions=secret,anotherOption,yetAnotherOption
```

One can configure a comma-delimited list of primary and secondary options that are available.  Currently, only a single option is supported in the `primaryOptions` list - the first listed value is always what is used.  The `secondaryOptions` list represents all supported methods of secondary authentication that a user could choose for themselves.  All options are expected to be implementations of `WebAuthenticationScheme`.

This scheme operates by first instantiating the first listed option in the `primaryOptions` configuration property, collecting user credentials, and authenticating to retrieve a valid "Candidate User".  The scheme then checks whether this user has a schemeId configured as their secondary authentication scheme, via a user property named `authentication.secondaryType`, the value of which is the `schemeId` of the scheme they have chosen.  If the user does not have anything defined for this, then secondary authentication is not done, and their authentication is completed successfully.  If the user does have a secondary type configured, then they are directed to authenticate using this configured scheme as well.

### Configuration Examples

#### Legacy UI (1.x) login page

```properties
authentication.scheme=basic
authentication.whiteList=/index.htm,/csrfguard,/**/*.js,/**/*.css,/**/*.gif,/**/*.jpg,/**/*.png,/**/*.ico
authentication.scheme.basic.type=org.openmrs.module.authentication.web.BasicWebAuthenticationScheme
authentication.scheme.basic.config.loginPage=/index.htm
authentication.scheme.basic.config.usernameParam=uname
authentication.scheme.basic.config.passwordParam=pw
```

#### Two-factor authentication example

```properties
authentication.scheme=2fa
authentication.whiteList=/**/authentication/basic.htm,/**/authentication/secret.htm,/csrfguard,/**/*.js,/**/*.css,/**/*.gif,/**/*.jpg,/**/*.png,/**/*.ico
authentication.scheme.2fa.type=org.openmrs.module.authentication.web.TwoFactorAuthenticationScheme
authentication.scheme.2fa.config.primaryOptions=basic
authentication.scheme.2fa.config.secondaryOptions=secret
authentication.scheme.basic.type=org.openmrs.module.authentication.web.BasicWebAuthenticationScheme
authentication.scheme.basic.config.loginPage=/module/myModule/loginBasic.htm
authentication.scheme.secret.type=org.openmrs.module.authentication.web.SecretQuestionAuthenticationScheme
authentication.scheme.secret.config.loginPage=/module/myModule/loginSecret.htm
```

### Tracking Active Users

All users who are actively logged into the system are tracked in a static variable.

`Map<String, UserLogin> activeLogins = UserLoginTracker.getActiveLogins();`

Implementations can choose to use this to track who is logged into the system, and various attributes of this authentication session, including:

* `loginId`:  The UUID identifying this authentication session
* `dateCreated`:  The date of first activity (typically when the login page was first accessed) during this session
* `loginDate`: The datetime the user successfully logged in during this session
* `logoutDate`: The datetime the user successfully logged out during this session
* `lastActivityDate`:  The datetime of the most recent HTTP request during this session
* `httpSessionId`: The HTTP session ID associated with this session
* `ipAddress`:  The IP address associated with this session
* `username`:  The username of the user for this session
* `events`:  A List of `AuthenticationEvent`, which consist of the event name and datetime, in order.  The events include:
  * `AUTHENTICATION_SUCCEEDED`:  Logged whenever an AuthenticationScheme authenticates successfully.  In a 2FA workflow, there may be multiple of these.
  * `AUTHENTICATION_FAILED`:  Logged whenever an AuthenticationScheme fails to authenticate successfully.
  * `LOGIN_SUCCEEDED`: Logged whenever a user is successfully authenticated against the Context and logged into the system
  * `LOGIN_FAILED`: Logged whenever a user fails to authenticate successfully against the Context
  * `LOGIN_EXPIRED`:  Logged whenever an active session expires and the user is passively logged out
  * `LOGOUT_SUCCEEDED`: Logged whenever a user actively logs out
  * `LOGOUT_FAILED`: Logged whenever a user tries to actively log out and this fails

### Logging

During the authentication process, this module adds additional logging that could be used to do more comprehensive tracking of authentication by users.  This logging is performed by the `org.openmrs.module.authentication.UserLogin` class/logger at level INFO.  Each logging event contains the following information in the logging context, which can be accessed in a log4j pattern layout via `%X{name}`

* `event`: The name of the authentication event.  See section above for the different types of events supported
* `schemeId`: If this is event is associated with a particular AuthenticationScheme, the schemeId is indicated here
* `loginId`: This is a UUID which can be used to associate all events that occur within the same authentication session
* `httpSessionId`:  This is the HTTP Session ID associated with this event.  This will be different before/after a user is successfully authenticated.
* `ipAddress`:  This is the IP Address associated with the client that is authenticating
* `username`:  This is either the username for unauthenticated credentials, or the username of the candidate or authenticated user for the authentication session
* `userId`:  If a candidate or authenticated user is associated with the authentication session, this is the userId of that user
* `lastActivityDate`: ISO formatted date of last user activity (based on most recent HTTP request timestamp)

All authentication events are given a log4j `Marker` named `AUTHENTICATION_EVENT`.

All authentication logging events have a `message` that outputs all the information in the logging context as a map.

#### Example of Logging to the Database

One way this logging can be utilized is to log authentication events to the OpenMRS database.  This can be done as follows:

Add a custom table - something like this:

```xml
<changeSet>
  <preConditions onFail="MARK_RAN">
    <not><tableExists tableName="authentication_event_log"/></not>
  </preConditions>
  <createTable tableName="authentication_event_log">
    <column name="login_id" type="char(36)">
      <constraints nullable="false"/>
    </column>
    <column name="event_datetime" type="datetime">
      <constraints nullable="false"/>
    </column>
    <column name="scheme_id" type="varchar(50)"/>
    <column name="ip_address" type="varchar(40)"/>
    <column name="http_session_id" type="varchar(32)"/>
    <column name="event_type" type="varchar(50)"/>
    <column name="username" type="varchar(50)"/>
    <column name="user_id" type="int"/>
  </createTable>
</changeSet>
```

Then, configure a `log4j2.xml` file within your application data directory (or within the configuration directory) with:

```xml
<Configuration xmlns="http://logging.apache.org/log4j/2.0/config">
  ...
  <Appenders>
    ...
    <JDBC name="AUTHENTICATION_EVENT_LOG" tableName="authentication_event_log">
      <ConnectionFactory class="org.openmrs.api.context.Context" method="getDatabaseConnection" />
      <Column name="login_id" pattern="%X{loginId}" />
      <Column name="event_datetime" isEventTimestamp="true" />
      <Column name="scheme_id" pattern="%X{schemeId}" />
      <Column name="ip_address" pattern="%X{ipAddress}" />
      <Column name="http_session_id" pattern="%X{httpSessionId}" />
      <Column name="event_type" pattern="%X{event}" />
      <Column name="username" pattern="%X{username}" />
      <ColumnMapping name="user_id" pattern="%X{userId}" type="java.lang.Integer" />
    </JDBC>
    ...
  </Appenders>
  <Loggers>
    ...
    <Logger name="org.openmrs.module.authentication.UserLogin" level="INFO">
      <AppenderRef ref="AUTHENTICATION_EVENT_LOG"/>
    </Logger>
    ...
  </Loggers>
</Configuration>
```
