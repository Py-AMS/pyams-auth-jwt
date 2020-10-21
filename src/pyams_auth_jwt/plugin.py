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
from pyramid.events import subscriber
from zope.container.contained import Contained
from zope.lifecycleevent import IObjectModifiedEvent
from zope.schema.fieldproperty import FieldProperty

from pyams_auth_jwt.interfaces import IJWTAuthenticationPlugin, IJWTSecurityConfiguration
from pyams_security.credential import Credentials
from pyams_security.interfaces import ICredentialsPlugin, ISecurityManager
from pyams_utils.adapter import adapter_config, get_annotation_adapter
from pyams_utils.factory import factory_config
from pyams_utils.property import ClassPropertyType, classproperty
from pyams_utils.registry import get_current_registry, query_utility, utility_config
from pyams_utils.wsgi import wsgi_environ_cache
from pyams_utils.zodb import volatile_property


__docformat__ = 'restructuredtext'

from pyams_security import _  # pylint: disable=ungrouped-imports


LOGGER = logging.getLogger('PyAMS (security)')

PARSED_CLAIMS_ENVKEY = 'pyams_auth_jwt.claims'
PARSED_CREDENTIALS_ENVKEY = "pyams_auth_jwt.credentials"


@factory_config(IJWTSecurityConfiguration)
class JWTSecurityConfiguration(Persistent, Contained):
    """JWT security configuration"""

    enabled = FieldProperty(IJWTSecurityConfiguration['enabled'])
    use_cookie = FieldProperty(IJWTSecurityConfiguration['use_cookie'])
    algorithm = FieldProperty(IJWTSecurityConfiguration['algorithm'])
    secret = FieldProperty(IJWTSecurityConfiguration['secret'])
    private_key = FieldProperty(IJWTSecurityConfiguration['private_key'])
    public_key = FieldProperty(IJWTSecurityConfiguration['public_key'])
    expiration = FieldProperty(IJWTSecurityConfiguration['expiration'])


@subscriber(IObjectModifiedEvent, context_selector=IJWTSecurityConfiguration)
def handle_modified_configuration(event):  # pylint: disable=unused-argument
    """Handle JWT configuration update"""
    plugin = query_utility(IJWTAuthenticationPlugin)
    if plugin is not None:
        del plugin.configuration


JWT_CONFIGURATION_KEY = 'pyams_auth_jwt.configuration'


@adapter_config(context=ISecurityManager, provides=IJWTSecurityConfiguration)
def securiy_manager_jwt_configuration_factory(context):
    """Security manager JWT configuration factory adapter"""
    return get_annotation_adapter(context, JWT_CONFIGURATION_KEY, IJWTSecurityConfiguration)


@utility_config(provides=IJWTAuthenticationPlugin)
@utility_config(name='jwt', provides=ICredentialsPlugin)
class JWTAuthenticationPlugin(metaclass=ClassPropertyType):
    """JWT authentication plugin"""

    prefix = 'jwt'
    title = _("JWT authentication credentials")

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
        """HTTP authication type setting"""
        return get_current_registry().settings.get('pyams.jwt.auth_type', 'Bearer')

    @volatile_property
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
        return configuration.enabled if (configuration is not None) else False

    @property
    def expiration(self):
        """Get default security manager expiration"""
        configuration = self.configuration
        # pylint: disable=no-member
        return configuration.expiration if configuration is not None else None

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

    @wsgi_environ_cache(PARSED_CLAIMS_ENVKEY)
    def get_claims(self, request):  # pylint: disable=too-many-return-statements
        """Get JWT claims"""
        if not self.enabled:
            return {}
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
            return claims
        except InvalidTokenError as exc:
            LOGGER.warning('Invalid JWT token from %s: %s', request.remote_addr, exc)
            return {}

    @wsgi_environ_cache(PARSED_CREDENTIALS_ENVKEY)
    def extract_credentials(self, request, **kwargs):  # pylint: disable=unused-argument
        """Extract principal ID from given request"""
        claims = self.get_claims(request)
        return Credentials(self.prefix,
                           claims.get('sub'),
                           login=claims.get('login')) if claims else None

    def authenticate(self, credentials, request):  # pylint: disable=unused-argument
        """Authenticate JWT token"""
        claims = self.get_claims(request)
        return claims.get('sub') if claims else None

    def unauthenticated_userid(self, request):
        """Get unauthenticated user ID"""
        claims = self.get_claims(request)
        return claims.get('sub') if claims else None


def create_jwt_token(request, principal, expiration=None, audience=None, **claims):
    # pylint: disable=unused-argument
    """Create JWT token"""
    plugin = query_utility(IJWTAuthenticationPlugin)
    if (plugin is not None) and plugin.enabled:
        return plugin.create_token(principal, expiration, audience, **claims)
    return None


def get_jwt_claims(request):
    """Get JWT claims"""
    plugin = query_utility(IJWTAuthenticationPlugin)
    if (plugin is not None) and plugin.enabled:
        return plugin.get_claims(request)
    return {}
