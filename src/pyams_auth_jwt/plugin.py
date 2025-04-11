#
# Copyright (c) 2015-2019 Thierry Florac <tflorac AT ulthar.net>
# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#

"""PyAMS_security.plugin.jwt module

This module provides a JWT authentication plug-in.
"""

import logging
from datetime import datetime, timedelta, timezone
from functools import partial, wraps

import jwt
from ZODB.POSException import ConnectionStateError
from jwt import InvalidTokenError
from persistent import Persistent
from pyramid.httpexceptions import HTTPUnauthorized
from zope.container.contained import Contained
from zope.location.interfaces import ISublocations
from zope.schema.fieldproperty import FieldProperty
from zope.traversing.interfaces import ITraversable

from pyams_auth_jwt.interfaces import ACCESS_OBJECT, IJWTAuthenticationPlugin, \
    IJWTClientKeyContainer, IJWTProxyHandler, IJWTSecurityConfiguration, JWT_CONFIGURATION_KEY, JWT_PREFIX
from pyams_security.credential import Credentials
from pyams_security.interfaces import ISecurityManager
from pyams_security.interfaces.plugin import ICredentialsPlugin, IDirectoryPlugin, IDirectorySearchPlugin
from pyams_utils.adapter import ContextAdapter, adapter_config, get_annotation_adapter
from pyams_utils.factory import factory_config
from pyams_utils.property import ClassPropertyType, classproperty
from pyams_utils.registry import get_current_registry, query_utility, utility_config

__docformat__ = 'restructuredtext'

from pyams_auth_jwt import _  # pylint: disable=ungrouped-imports


LOGGER = logging.getLogger('PyAMS (JWT security)')

PARSED_CLAIMS_ENVKEY = 'pyams_auth_jwt.claims'
PARSED_CREDENTIALS_ENVKEY = "pyams_auth_jwt.credentials"


@factory_config(IJWTSecurityConfiguration)
class JWTSecurityConfiguration(Persistent, Contained):
    """JWT security configuration"""

    audience = FieldProperty(IJWTSecurityConfiguration['audience'])
    access_token_name = FieldProperty(IJWTSecurityConfiguration['access_token_name'])
    refresh_token_name = FieldProperty(IJWTSecurityConfiguration['refresh_token_name'])
    
    local_mode = FieldProperty(IJWTSecurityConfiguration['local_mode'])
    algorithm = FieldProperty(IJWTSecurityConfiguration['algorithm'])
    secret = FieldProperty(IJWTSecurityConfiguration['secret'])
    private_key = FieldProperty(IJWTSecurityConfiguration['private_key'])
    public_key = FieldProperty(IJWTSecurityConfiguration['public_key'])
    access_expiration = FieldProperty(IJWTSecurityConfiguration['access_expiration'])
    refresh_expiration = FieldProperty(IJWTSecurityConfiguration['refresh_expiration'])

    proxy_mode = FieldProperty(IJWTSecurityConfiguration['proxy_mode'])
    authority = FieldProperty(IJWTSecurityConfiguration['authority'])
    get_token_service = FieldProperty(IJWTSecurityConfiguration['get_token_service'])
    proxy_access_token_name = FieldProperty(IJWTSecurityConfiguration['proxy_access_token_name'])
    get_claims_service = FieldProperty(IJWTSecurityConfiguration['get_claims_service'])
    refresh_token_service = FieldProperty(IJWTSecurityConfiguration['refresh_token_service'])
    proxy_refresh_token_name = FieldProperty(IJWTSecurityConfiguration['proxy_refresh_token_name'])
    verify_token_service = FieldProperty(IJWTSecurityConfiguration['verify_token_service'])
    verify_ssl = FieldProperty(IJWTSecurityConfiguration['verify_ssl'])
    use_cache = FieldProperty(IJWTSecurityConfiguration['use_cache'])
    selected_cache = FieldProperty(IJWTSecurityConfiguration['selected_cache'])

    @property
    def enabled(self):
        """Check if configuration is enabled"""
        return self.local_mode or self.proxy_mode


@adapter_config(required=ISecurityManager,
                provides=IJWTSecurityConfiguration)
def securiy_manager_jwt_configuration_factory(context):
    """Security manager JWT configuration factory adapter"""
    return get_annotation_adapter(context, JWT_CONFIGURATION_KEY, IJWTSecurityConfiguration,
                                  name='++jwt++')


@adapter_config(name='jwt',
                required=ISecurityManager,
                provides=ITraversable)
class JWTSecurityConfigurationTraverser(ContextAdapter):
    """JWT security configuration traverser"""
    
    def traverse(self, name, furtherPath=None):
        return IJWTSecurityConfiguration(self.context, None)


@adapter_config(name='jwt',
                required=ISecurityManager,
                provides=ISublocations)
class JWTSecurityConfigurationSublocations(ContextAdapter):
    """JWT security configuration sublocations"""
    
    def sublocations(self):
        configuration = IJWTSecurityConfiguration(self.context, None)
        if configuration is not None:
            yield from configuration


def check_enabled(func=None, *, default=None):
    """Decorator to check for enabled plugin"""
    if func is None:
        return partial(check_enabled, default=default)

    @wraps(func)
    def wrapper(plugin, *args, **kwargs):
        if not plugin.enabled:
            return default() if default is not None else None
        return func(plugin, *args, **kwargs)
    return wrapper


def check_prefix(func=None, *, default=None):
    """Decorator to check for principal ID prefix"""
    if func is None:
        return partial(check_prefix, default=default)

    @wraps(func)
    def wrapper(plugin, principal_id, *args, **kwargs):
        if not principal_id.startswith(f'{JWT_PREFIX}:'):
            return default() if default is not None else None
        return func(plugin, principal_id, *args, **kwargs)
    return wrapper


@utility_config(provides=IJWTAuthenticationPlugin)
@utility_config(name='jwt', provides=ICredentialsPlugin)
@utility_config(name='jwt', provides=IDirectoryPlugin)
class JWTAuthenticationPlugin(metaclass=ClassPropertyType):
    """JWT authentication plugin"""

    prefix = JWT_PREFIX
    title = _("JWT authentication")

    leeway = 0
    callback = None
    json_encoder = None

    @property
    def audience(self):
        """Audience getter"""
        configuration = self.configuration
        return configuration.audience if (configuration is not None) else None
    
    @classproperty
    def http_header(cls):  # pylint: disable=no-self-argument,no-self-use
        """HTTP header setting"""
        return get_current_registry().settings.get('pyams_auth_jwt.http_header', 'Authorization')

    @classproperty
    def auth_type(cls):  # pylint: disable=no-self-argument,no-self-use
        """HTTP authentication type setting"""
        return get_current_registry().settings.get('pyams_auth_jwt.auth_type', 'Bearer')

    @property
    def configuration(self):  # pylint: disable=no-self-use
        """JWT configuration getter"""
        try:
            manager = query_utility(ISecurityManager)
            if manager is not None:
                return IJWTSecurityConfiguration(manager)
        except ConnectionStateError:
            return None
        return None

    @property
    def enabled(self):
        """Check if JWT authentication is enabled in security manager"""
        configuration = self.configuration
        # pylint: disable=no-member
        try:
            return configuration.enabled if (configuration is not None) else False
        except ConnectionStateError:
            return False

    @property
    def expiration(self):
        """Get default security manager expiration"""
        configuration = self.configuration
        # pylint: disable=no-member
        return configuration.access_expiration if configuration is not None else None

    def create_token(self, principal, expiration=None, audience=None, **claims):
        """Create JWT token"""
        if not self.enabled:
            return None
        configuration = self.configuration
        payload = {}
        payload.update(claims)
        payload['sub'] = principal
        payload['iat'] = iat = datetime.now(timezone.utc)
        expiration = expiration or self.expiration
        if expiration:
            if not isinstance(expiration, timedelta):
                expiration = timedelta(seconds=expiration)
            payload['exp'] = iat + expiration
        audience = audience or self.audience
        if audience:
            payload['aud'] = audience
        # pylint: disable=no-member
        algorithm = configuration.algorithm if configuration is not None else 'RS512'
        if algorithm.startswith('HS'):
            # pylint: disable=no-member
            key = configuration.secret if configuration is not None else None
        else:  # RS*/ES*
            # pylint: disable=no-member
            key = configuration.private_key if configuration is not None else None
        token = jwt.encode(payload, key, algorithm=algorithm, json_encoder=self.json_encoder)
        if not isinstance(token, str):
            token = token.decode('ascii')
        return token

    def _get_claims(self, request, obj=None):  # pylint: disable=too-many-return-statements
        """Get JWT claims"""
        if self.http_header == 'Authorization':  # pylint: disable=comparison-with-callable
            try:
                if request.authorization is None:
                    return {}
            except (ValueError, AttributeError):  # invalid authorization header
                return {}
            (auth_type, token) = request.authorization
            if auth_type != self.auth_type:  # pylint: disable=comparison-with-callable
                return {}
        else:
            token = request.headers.get(self.http_header)
        if not token:
            return {}
        try:
            header = jwt.get_unverified_header(token)
            key_id = header.get('kid')
            if key_id:
                container = IJWTClientKeyContainer(self.configuration, None)
                if container is None:
                    return {}
                client_key = container.get(key_id)
                if (client_key is None) or not client_key.active:
                    return {}
                key = client_key.public_key
                claims = jwt.decode(token, key,
                                    algorithms=[client_key.algorithm],
                                    leeway=self.leeway,
                                    issuer=client_key.issuer,
                                    audience=client_key.audience)
                principal = client_key.get_principal(request)
                if principal is not None:
                    claims['sub'] = principal.id
            else:
                configuration = self.configuration
                # pylint: disable=no-member
                algorithm = configuration.algorithm if configuration is not None else 'RS512'
                if algorithm.startswith('HS'):
                    # pylint: disable=no-member
                    key = configuration.secret if configuration is not None else None
                else:  # RS*/ES*
                    # pylint: disable=no-member
                    key = configuration.public_key if configuration is not None else None
                claims = jwt.decode(token, key,
                                    algorithms=[algorithm],
                                    leeway=self.leeway,
                                    audience=self.audience)
            if obj and obj != claims.get('obj'):
                raise InvalidTokenError('Bad token object!')
            return claims
        except InvalidTokenError as exc:
            LOGGER.warning('Invalid JWT token from %s: %s',
                           getattr(request, 'remote_addr', '--'), exc)
            return {}

    def get_claims(self, request, obj=None):  # pylint: disable=too-many-return-statements
        """Get JWT claims"""
        configuration = self.configuration
        if configuration is None:
            return {}
        if configuration.proxy_mode:
            handler = IJWTProxyHandler(self, None)
            if handler is not None:
                _status_code, claims = handler.get_claims(request, obj)  # pylint: disable=assignment-from-no-return
                return claims
        elif configuration.local_mode:
            return self._get_claims(request, obj)
        return {}

    def extract_credentials(self, request, **kwargs):  # pylint: disable=unused-argument
        """Extract principal ID from given request"""
        claims = self.get_claims(request, obj=ACCESS_OBJECT)
        if claims:
            return Credentials(self.prefix,
                               claims.get('sub'),
                               login=claims.get('login')) if claims else None
        return None

    @check_enabled
    def authenticate(self, credentials, request):  # pylint: disable=unused-argument
        """Authenticate JWT token"""
        claims = self.get_claims(request, obj=ACCESS_OBJECT)
        return claims.get('sub') if claims else None

    @check_enabled
    @check_prefix
    def get_principal(self, principal_id, info=True):
        """Returns real principal matching given ID, or None"""
        container = IJWTClientKeyContainer(self.configuration, None)
        if container is None:
            return None
        prefix, name = principal_id.split(':', 1)
        client_key = container.get(name)
        if client_key is None:
            return None
        if info:
            return client_key.get_principal()
        return client_key

    @check_enabled(default=set)
    @check_prefix(default=set)
    def get_all_principals(self, principal_id):
        """Returns all principals matching given principal ID"""
        result = set()
        container = IJWTClientKeyContainer(self.configuration, None)
        if container is None:
            return result
        prefix, name = principal_id.split(':', 1)
        client_key = container.get(name)
        if (client_key is not None) and client_key.active:
            result.add(principal_id)
            principal = client_key.get_principal()
            if principal is not None:
                result.add(principal.id)
        return result

    @check_enabled
    def find_principals(self, query, exact_match=False):
        """Find principals matching given query"""
        if not query:
            return
        container = IJWTClientKeyContainer(self.configuration, None)
        if container is None:
            return
        query = query.lower()
        for client_key in container.values():
            if not client_key.active:
                continue
            for attr in (client_key.key_id, client_key.label):
                if not attr:
                    continue
                if (exact_match and query == attr.lower()) or \
                        (not exact_match and query in attr.lower()):
                    yield client_key.get_principal(allow_redirect=False)
                    break


@adapter_config(required=IJWTAuthenticationPlugin,
                provides=IJWTSecurityConfiguration)
def jwt_plugin_configuration_adapter(context):
    """JWT plugin configuration adapter"""
    return context.configuration


def create_jwt_token(request, principal, expiration=None, audience=None, **claims):
    # pylint: disable=unused-argument
    """Create JWT token"""
    plugin = query_utility(IJWTAuthenticationPlugin)
    if (plugin is not None) and plugin.enabled:
        return plugin.create_token(principal, expiration, audience, **claims)
    return None


def get_jwt_claims(request, obj=None):
    """Get JWT claims"""
    plugin = query_utility(IJWTAuthenticationPlugin)
    if (plugin is not None) and plugin.enabled:
        return plugin.get_claims(request, obj=obj)
    return {}


def jwt_object_view(view, info):
    """JWT object view deriver
    
    This filter is raising an HTTP Unauthorized exception if required JWT
    token object is not provided by the incoming request
    """
    jwt_object = info.options.get('jwt_object')
    if jwt_object:
        def view_wrapper(context, request):
            claims = get_jwt_claims(request, obj=jwt_object)
            if not claims:
                raise HTTPUnauthorized
            return view(context, request)
        return view_wrapper
    return view
    
jwt_object_view.options = ('jwt_object',)
