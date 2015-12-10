# flask-secuREST
REST Security implementation for REST Gateway

This security framework integrates with [Flask-RESTful](https://flask-restful.readthedocs.org/en/0.3.2/) to secure REST services.


## Main Concepts

### Userstore
Generally, a userstore is a class that enables loading of user details and returns them as a user object.

Typically (but not always) user details are stored as records in a database or objects in a directory. Each user can
be identified by a unique attribute, such as a username or id, or by a unique combination of attributes.<br>
In order to authenticate a user (for example by a set of username and password) it might be required to load the user's
details and verify the given credentials indeed match.<br>

### Authentication Provider
An Authentication Provider is a class that performs authentication. Multiple authentication providers can be configured
in order to support multiple authentication methods (e.g. password, token, Kerberos).<br>
When a REST call is received by the REST service, the Flask-secuREST will attempt to authenticate it using the
configured authentication providers. If the first authenticator fails the second one will be attempted, and so on.
The authentication provider has access to the userstore instance (if configured) and can use it to get user details and
use them to perform authentication.<br>
For example, it can compare the given password to the one found on the userstore or verify the user is still active
(in many environments users are marked as "inactive", instead of deleting the account entirely).


Once an authenticator can successfully authenticate the request's user - it should return the user object and allow the
request to be completed. Other authenticators will not be called until the next request is processed.
If none of the authenticators can successfully authenticate the request - the request does not reach its endpoint and
the client receives an "Unauthorized User" error.


>
	Note:
	We mentioned Token as an authentication method. 
	But in order to send a token with each request, the user must first receive a token. 
	Tokens can be generated by many systems, 
	and they will work as long as the token can be processed by one of the 
	registered authentication providers.


### Authorization Provider
After authenticating the request's user, authorization will take place, if an authorization provider is configured.
An authorization provider is used to verify that the user is permitted to execute the requested method (e.g. *GET*)
on the requested endpoint.

## Writing your own userstore and authentication providers

### Custom Userstore Implementation

A userstore driver is a class that loads user details and returns them as a user object.<br>
A valid userstore implementation is a:
- Python class
- Inherits from [AbstractUserstore](https://github.com/cloudify-cosmo/flask-securest/blob/0.7/flask_securest/userstores/abstract_userstore.py)
- Implements `get_user(self, identifier)`, which returns a user object containing a dictionary of user details read from the userstore.
    If a matching user is not found, `get_user` should return None.

An example for a userstore class based on dictionary - [SimpleUserstore](https://github.com/cloudify-cosmo/flask-securest/blob/0.7/flask_securest/userstores/simple.py).

### Custom Authentication Provider Implementation

An Authentication Provider is a class that performs authentication.
A valid authentication provider implementation is a:

- Python class
- Inherits from [AbstractAuthenticationProvider]
(https://github.com/cloudify-cosmo/flask-securest/blob/0.7/flask_securest/authentication_providers/abstract_authentication_provider.py)
- Implements `authenticate(self, userstore=None)`, which returns a unique user identifier (e.g. username) if authentication was successful,
and raises an exception if it failed.
Exception messages should be informative but not expose confidential user or system details. For example: "Request authentication header
is empty or missing" is OK, while "username jason attempted to use wrong password 123456" reveals too much information.

>
An example authentication provider based on password authentication -
[PasswordAuthenticator](https://github.com/cloudify-cosmo/flask-securest/blob/0.7/flask_securest/authentication_providers/password.py)

### Custom Authorization Provider Implementation

An authorization provider is a class that performs the authorization logic, after user authenticity has been verified.
Authorization should evaluate if the acting user is allowed to execute the requested methods (e.g. POST) on the requested endpoint.
A valid authorization provider is a:

- Python class
- Inherits from [AbstractAuthorizationProvider]
(https://github.com/cloudify-cosmo/flask-securest/blob/0.7/flask_securest/authorization_providers/abstract_authorization_provider.py)
- Implements `authorize(self)`, which returns true if the user is authorized, or false otherwise.

>
An example role-based authorization provider -
[RoleBasedAuthorizationProvider](https://github.com/cloudify-cosmo/flask-securest/blob/0.7/flask_securest/authorization_providers/role_based_authorization_provider.py)
