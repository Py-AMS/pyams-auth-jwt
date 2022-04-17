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
from datetime import datetime, timedelta

import jwt
from ZODB.POSException import ConnectionStateError
from jwt import InvalidTokenError
from persistent import Persistent
from zope.container.contained import Contained
from zope.schema.fieldproperty import FieldProperty

from pyams_auth_jwt.interfaces import ACCESS_OBJECT, IJWTAuthenticationPlugin, \
    IJWTProxyHandler, IJWTSecurityConfiguration, JWT_CONFIGURATION_KEY
from pyams_security.credential import Credentials
from pyams_security.interfaces import ISecurityManager
from pyams_security.interfaces.plugin import ICredentialsPlugin
from pyams_utils.adapter import adapter_config, get_annotation_adapter
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

    local_mode = FieldProperty(IJWTSecurityConfiguration['local_mode'])
    algorithm = FieldProperty(IJWTSecurityConfiguration['algorithm'])
    secret = FieldProperty(IJWTSecurityConfiguration['secret'])
    private_key = FieldProperty(IJWTSecurityConfiguration['private_key'])
    public_key = FieldProperty(IJWTSecurityConfiguration['public_key'])
    access_expiration = FieldProperty(IJWTSecurityConfiguration['access_expiration'])
    access_token_name = FieldProperty(IJWTSecurityConfiguration['access_token_name'])
    refresh_expiration = FieldProperty(IJWTSecurityConfiguration['refresh_expiration'])
    refresh_token_name = FieldProperty(IJWTSecurityConfiguration['refresh_token_name'])

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


@adapter_config(required=ISecurityManager, provides=IJWTSecurityConfiguration)
def securiy_manager_jwt_configuration_factory(context):
    """Security manager JWT configuration factory adapter"""
    return get_annotation_adapter(context, JWT_CONFIGURATION_KEY, IJWTSecurityConfiguration)


@utility_config(provides=IJWTAuthenticationPlugin)
@utility_config(name='jwt', provides=ICredentialsPlugin)
class JWTAuthenticationPlugin(metaclass=ClassPropertyType):
    """JWT authentication plugin"""

    prefix = 'jwt'
    title = _("JWT authentication")

    audience = None
    leeway = 0
    callback = None
    json_encoder = None

    @classproperty
    def http_header(cls):  # pylint: disable=no-self-argument,no-self-use
        """HTTP header setting"""
        return get_current_registry().settings.get('pyams.jwt.http_header', 'Authorization')

    @classproperty
    def auth_type(cls):  # pylint: disable=no-self-argument,no-self-use
        """HTTP authentication type setting"""
        return get_current_registry().settings.get('pyams.jwt.auth_type', 'Bearer')

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
        payload['iat'] = iat = datetime.utcnow()
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
        else:  # RS256
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
            configuration = self.configuration
            # pylint: disable=no-member
            algorithm = configuration.algorithm if configuration is not None else 'RS512'
            if algorithm.startswith('HS'):
                # pylint: disable=no-member
                key = configuration.secret if configuration is not None else None
            else:  # RS256/RS512
                # pylint: disable=no-member
                key = configuration.public_key if configuration is not None else None
            claims = jwt.decode(token, key, algorithms=[algorithm],
                                leeway=self.leeway, audience=self.audience)
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
            handler = IJWTProxyHandler(self)
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

    def authenticate(self, credentials, request):  # pylint: disable=unused-argument
        """Authenticate JWT token"""
        claims = self.get_claims(request, obj=ACCESS_OBJECT)
        return claims.get('sub') if claims else None

    def unauthenticated_userid(self, request):
        """Get unauthenticated user ID"""
        claims = self.get_claims(request, obj=ACCESS_OBJECT)
        return claims.get('sub') if claims else None


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


class JWTTokenObjectPredicate:
    """JWT token object predicate

    This filter is used to filter JWT tokens based on their "obj" attribute.
    """

    def __init__(self, obj, config):  # pylint: disable=unused-argument
        self.obj = obj

    def text(self):
        """Predicate text output"""
        return 'jwt_object = %s' % (self.obj,)

    phash = text

    def __call__(self, context, request):
        obj = self.obj
        if obj:
            claims = get_jwt_claims(request, obj=obj)
            if claims:
                return True
        return False
