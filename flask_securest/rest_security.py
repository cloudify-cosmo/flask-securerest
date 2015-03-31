#########
# Copyright (c) 2015 GigaSpaces Technologies Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
#  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  * See the License for the specific language governing permissions and
#  * limitations under the License.

from collections import namedtuple
from functools import wraps
from flask import current_app
from flask_restful import Resource
from userstores.abstract_userstore import AbstractUserstore
from authentication_providers.abstract_authentication_provider \
    import AbstractAuthenticationProvider


# TODO decide which of the below 'abort' is better?
# TODO the werkzeug abort is referred to by flask's
# from werkzeug.exceptions import abort
from flask import abort, request, _request_ctx_stack
from flask.ext.securest.models import AnonymousUser


#: Default name of the auth header (``Authorization``)
AUTH_HEADER_NAME = 'Authorization'
AUTH_TOKEN_HEADER_NAME = 'Authentication-Token'

SECRET_KEY = 'SECUREST_SECRET_KEY'
SECURED_MODE = 'SECUREST_MODE'

# TODO is this required?
# PERMANENT_SESSION_LIFETIME = datetime.timedelta(seconds=30)

SECURED = 'secured'
VIEW_CLASS = 'view_class'

secured_resources = []


class SecuREST(object):

    def __init__(self, app=None):
        self.app = app
        self.app.securest_unauthorized_user_handler = None
        self.app.securest_authentication_providers = []
        self.app.request_security_bypass_handler = None

        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        app.config[SECURED_MODE] = True

        # app.teardown_appcontext(self.teardown)
        app.before_first_request(validate_configuration)
        app.before_request(authenticate_request_if_needed)
        app.after_request(filter_response_if_needed)

    # TODO perform teardown operations if required
    # using def teardown(self, exception)
    # log the exception if not None/empty?

    # TODO make property
    def unauthorized_user_handler(self, unauthorized_user_handler):
        self.app.securest_unauthorized_user_handler = unauthorized_user_handler

    @property
    def request_security_bypass_handler(self):
        return self.app.request_security_bypass_handler

    @request_security_bypass_handler.setter
    def request_security_bypass_handler(self, value):
        self.app.request_security_bypass_handler = value

    def set_userstore_driver(self, userstore):
        """
        Registers the given userstore driver.
        :param userstore: the userstore driver to be set
        """
        if not isinstance(userstore, AbstractUserstore):
            err_msg = 'failed to register userstore driver "{0}", Error: ' \
                      'driver does not inherit "{1}"'\
                .format(get_instance_class_fqn(userstore),
                        get_class_fqn(AbstractUserstore))
            self.app.logger.error(err_msg)
            raise Exception(err_msg)

        self.app.securest_userstore_driver = userstore

    def register_authentication_provider(self, provider):
        """
        Registers the given authentication method.
        :param provider: appends the given authentication provider to the list
         of providers
        NOTE: Pay attention to the order of the registered providers!
        authentication will be attempted on each of the registered providers,
        according to their registration order, until successful.
        """
        if not isinstance(provider, AbstractAuthenticationProvider):
            err_msg = 'failed to register authentication provider "{0}", ' \
                      'Error: provider does not inherit "{1}"'\
                .format(get_instance_class_fqn(provider),
                        get_class_fqn(AbstractAuthenticationProvider))
            self.app.logger.error(err_msg)
            raise Exception(err_msg)

        self.app.securest_authentication_providers.append(provider)


def validate_configuration():
    if not current_app.securest_authentication_providers:
        raise Exception('authentication methods not set')


def authenticate_request_if_needed():

    if not current_app.config.get(SECURED_MODE):
        current_app.logger.debug('secured mode is off, not setting user')
    else:
        from flask import globals
        g_request = globals.request
        endpoint = g_request.endpoint
        current_app.logger.debug('authenticating request to endpoint: {0}'
                                 .format(endpoint))
        view_func = current_app.view_functions.get(endpoint)

        if not view_func:
            raise Exception('endpoint {0} is not mapped to a REST resource'
                            .format(endpoint))

        if not hasattr(view_func, VIEW_CLASS):
            raise Exception('view_class attribute not found on view func {0}'
                            .format(view_func))

        resource_class = getattr(view_func, VIEW_CLASS)
        if hasattr(resource_class, SECURED) \
                and getattr(resource_class, SECURED):
            current_app.logger.debug('accessing secured resource {0}, '
                                     'attempting authentication'.format(
                                         get_class_fqn(resource_class)))
            authenticate_request()
        else:
            current_app.logger.debug('accessing open resource {0}, setting '
                                     'anonymous user'.format(
                                         get_class_fqn(resource_class)))
            set_anonymous_user()

'''
def secured(resource_class):
    current_app.logger.debug('adding resource to secured_resources: {0}'
                             .format(utils.get_class_fqn(resource_class)))
    global secured_resources
    secured_resources.append(utils.get_class_fqn(resource_class))

    return resource_class
'''


def filter_response_if_needed(response=None):
    return response


def get_request_user():
    request_user = None
    # TODO is there a nicer way to do this?
    request_ctx = _request_ctx_stack.top
    if hasattr(request_ctx, 'user'):
        request_user = request_ctx.user

    return request_user


def is_authenticated():
    authenticated = False
    current_user = get_request_user()

    if current_user and \
            not isinstance(current_user, AnonymousUser):
        authenticated = True

    return authenticated


def filter_results(results):
    return results


def auth_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if _is_secured_request_context():
            try:
                auth_info = get_auth_info_from_request()
                authenticate(current_app.securest_authentication_providers,
                             auth_info)
            except Exception:
                handle_unauthorized_user()
            result = func(*args, **kwargs)
            return filter_results(result)
        else:
            # rest security turned off
            return func(*args, **kwargs)
    return wrapper


def _is_secured_request_context():
    return current_app.config.get(SECURED_MODE) and not \
        (current_app.request_security_bypass_handler and
         current_app.request_security_bypass_handler(request))


def handle_unauthorized_user():
    if current_app.securest_unauthorized_user_handler:
        current_app.securest_unauthorized_user_handler()
    else:
        # TODO verify this ends up in resources.abort_error
        # TODO do this? from flask_restful import abort
        abort(401)


def get_auth_info_from_request():
    user_id = None
    password = None
    token = None

    # TODO remember this is configurable - document
    app_config = current_app.config

    auth_header_name = app_config.get('AUTH_HEADER_NAME', AUTH_HEADER_NAME)
    if auth_header_name:
        auth_header = request.headers.get(auth_header_name)

    auth_token_header_name = app_config.get('AUTH_TOKEN_HEADER_NAME',
                                            AUTH_TOKEN_HEADER_NAME)
    if auth_token_header_name:
        token = request.headers.get(auth_token_header_name)

    if not auth_header and not token:
        raise Exception('Failed to get authentication information from '
                        'request, headers not found: {0}, {1}'
                        .format(auth_header_name, auth_token_header_name))

    if auth_header:
        auth_header = auth_header.replace('Basic ', '', 1)
        try:
            from itsdangerous import base64_decode
            api_key = base64_decode(auth_header)
            # TODO parse better, with checks and all, this is shaky
        except TypeError:
            pass
        else:
            api_key_parts = api_key.split(':')
            user_id = api_key_parts[0]
            password = api_key_parts[1]

    auth_info = namedtuple('auth_info_type',
                           ['user_id', 'password', 'token'])

    return auth_info(user_id, password, token)


def authenticate_request():
    auth_info = get_auth_info_from_request()

    try:
        user = authenticate(current_app.securest_authentication_providers,
                            auth_info)
        # TODO make sure this doesn't print all user props, just the username
        current_app.logger.debug('authenticated user: {0}'.format(user))
    except Exception:
        current_app.logger.warning('authentication failed, setting anonymous '
                                   'user')
        set_anonymous_user()
    else:
        _request_ctx_stack.top.user = user


def set_anonymous_user():
    _request_ctx_stack.top.user = AnonymousUser()


def authenticate(authentication_providers, auth_info):
    user = None
    userstore_driver = None
    for auth_provider in authentication_providers:
        try:
            if hasattr(current_app, 'securest_userstore_driver'):
                userstore_driver = current_app.securest_userstore_driver
                current_app.logger.debug('authenticating vs userstore: {0}'
                                         .format(userstore_driver))
            else:
                current_app.logger.debug('authenticating without userstore')
            user = auth_provider.authenticate(auth_info, userstore_driver)
            break
        except Exception:
            # logging a general error, not to expose account info
            current_app.logger.debug('failed to authenticate user using {0}'
                                     .format(auth_provider))
            continue  # try the next authentication method until successful

    if not user:
        raise Exception('Unauthorized')

    return user


def get_instance_class_fqn(instance):
    instance_cls = instance.__class__
    return instance_cls.__module__ + '.' + instance_cls.__name__


def get_class_fqn(clazz):
    return clazz.__module__ + '.' + clazz.__name__


class SecuredResource(Resource):
    secured = True
    method_decorators = [auth_required]
