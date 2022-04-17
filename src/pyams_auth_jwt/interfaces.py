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

"""PyAMS JWT authentication package.interfaces module

This module provides public interfaces.
"""

from zope.interface import Attribute, Interface, Invalid, invariant
from zope.schema import Bool, Choice, Int, Text, TextLine

from pyams_security.interfaces.plugin import IAuthenticationPlugin
from pyams_utils.cache import BEAKER_CACHES_VOCABULARY
from pyams_utils.schema import HTTPMethodField


__docformat__ = 'restructuredtext'

from pyams_auth_jwt import _


#
# API endpoints
#

REST_TOKEN_ROUTE = 'jwt.rest.token'
REST_VERIFY_ROUTE = 'jwt.rest.verify'


#
# JWT authentication utility interface
#

JWT_CONFIGURATION_KEY = 'pyams_auth_jwt.configuration'
"""Main JWT configuration key"""

ACCESS_OBJECT = 'access'
"""Object of JWT token used for authentication"""

ACCESS_TOKEN_NAME = 'accessToken'
"""Default name of JSON access token attribute"""

REFRESH_OBJECT = 'refresh'
"""Object of JWT token used for refresh"""

REFRESH_TOKEN_NAME = 'refreshToken'
"""Default name of JSON refresh token attribute"""

JWT_PROXY_CACHE_NAME = 'jwt_tokens'
"""Name of the Beaker cache used to store validated tokens"""

JWT_PROXY_TOKENS_NAMESPACE = 'PyAMS-auth-jwt::tokens'
"""Cache namespace used to store validated tokens"""


class IJWTProxyHandler(Interface):
    """JWT proxy handler"""

    def get_claims(self, request, obj=None):
        """Get claims from given request authorization header"""

    def get_tokens(self, request, credentials):
        """Get new tokens from authentication authority"""

    def refresh_token(self, request):
        """Get new access token with refresh token authorization"""


class IJWTSecurityConfiguration(Interface):
    """Security manager configuration interface for JWT"""

    access_token_name = TextLine(title=_("Access token attribute"),
                                 description=_("Name of the JSON attribute containing "
                                               "access token returned by REST APIs"),
                                 required=False,
                                 default=ACCESS_TOKEN_NAME)

    refresh_token_name = TextLine(title=_("Refresh token attribute"),
                                  description=_("Name of the JSON attribute containing "
                                                "refresh token returned by REST APIs"),
                                  required=False,
                                  default=REFRESH_TOKEN_NAME)

    enabled = Attribute("Enabled configuration?")

    local_mode = Bool(title=_("Enable JWT direct authentication?"),
                      description=_("Enable direct login via JWT authentication"),
                      required=False,
                      default=False)

    algorithm = Choice(title=_("JWT encoding algorithm"),
                       description=_("HS* protocols are using the secret, while RS* protocols "
                                     "are using RSA keys"),
                       required=False,
                       values=('RS256', 'RS512', 'HS256', 'HS512'),
                       default='RS512')

    secret = TextLine(title=_("JWT secret"),
                      description=_("This secret is required when using HS* encryption"),
                      required=False)

    private_key = Text(title=_("JWT private key"),
                       description=_("The secret key is required when using RS* algorithm"),
                       required=False)

    public_key = Text(title=_("JWT public key"),
                      description=_("The public key is required when using RS* algorithm"),
                      required=False)

    access_expiration = Int(title=_("Access token lifetime"),
                            description=_("JWT access token lifetime, in seconds"),
                            required=False,
                            default=60 * 60)

    refresh_expiration = Int(title=_("Refresh token lifetime"),
                             description=_("JWT refresh token lifetime, in seconds"),
                             required=False,
                             default=60 * 60 * 24 * 7)

    proxy_mode = Bool(title=_("Enable JWT proxy authentication?"),
                      description=_("If this option is enabled, tokens management requests "
                                    "will be forwarded to another authentication authority"),
                      required=False,
                      default=False)

    authority = TextLine(title=_("Authentication authority"),
                         description=_("Base URL (protocol and hostname) of the authentication "
                                       "authority to which tokens management requests will be "
                                       "forwarded"),
                         required=False)

    get_token_service = HTTPMethodField(title=_("Token getter service"),
                                        description=_("REST HTTP service used to get a new token"),
                                        required=False,
                                        default=('POST', '/api/auth/jwt/token'))

    proxy_access_token_name = TextLine(title=_("Access token attribute"),
                                       description=_("Name of the JSON attribute returned by "
                                                     "REST API containing access tokens"),
                                       required=False,
                                       default=ACCESS_TOKEN_NAME)

    proxy_refresh_token_name = TextLine(title=_("Refresh token attribute"),
                                        description=_("Name of the JSON attribute returned by "
                                                      "REST API containing refresh tokens"),
                                        required=False,
                                        default=REFRESH_TOKEN_NAME)

    get_claims_service = HTTPMethodField(title=_("Token claims getter"),
                                         description=_("REST HTTP service used to extract claims "
                                                       "from provided authorization token"),
                                         required=False,
                                         default=('GET', '/api/auth/jwt/token'))

    refresh_token_service = HTTPMethodField(title=_("Token refresh service"),
                                            description=_("REST HTTP service used to get a new "
                                                          "access token with a refresh token"),
                                            required=False,
                                            default=('PATCH', '/api/auth/jwt/token'))

    verify_token_service = HTTPMethodField(title=_("Token verify service"),
                                           description=_("REST HTTP service used to check "
                                                         "validity of an existing token"),
                                           required=False,
                                           default=('POST', '/api/auth/jwt/verify'))

    verify_ssl = Bool(title=_("Verify SSL?"),
                      description=_("If 'no', SSL certificates will not be verified"),
                      required=False,
                      default=True)

    use_cache = Bool(title=_("Use verified tokens cache?"),
                     description=_("If selected, this option allows to store credentials in a "
                                   "local cache from which they can be reused"),
                     required=False,
                     default=True)

    selected_cache = Choice(title=_("Selected tokens cache"),
                            description=_("Beaker cache selected to store validated tokens"),
                            required=False,
                            vocabulary=BEAKER_CACHES_VOCABULARY,
                            default='default')

    @invariant
    def check_configuration(self):
        """Check for JWT configuration"""
        if self.local_mode and self.proxy_mode:
            raise Invalid(_("You can't enable both local and proxy modes"))
        if self.local_mode:
            if not self.algorithm:
                raise Invalid(_("You must choose an algorithm to enable JWT authentication"))
            if self.algorithm.startswith('HS'):  # pylint: disable=no-member
                if not self.secret:
                    raise Invalid(_("You must define JWT secret to use HS256 algorithm"))
            elif self.algorithm.startswith('RS'):  # pylint: disable=no-member
                if not (self.private_key and self.public_key):
                    raise Invalid(_("You must define a private and a public key to use "
                                    "RS256 algorithm"))
        if self.proxy_mode:
            if not self.authority:
                raise Invalid(_("You must define authentication authority to use proxy mode"))
            if self.use_cache and not self.selected_cache:
                raise Invalid(_("You must choose a cache to enable tokens caching"))


class IJWTAuthenticationPlugin(IAuthenticationPlugin):
    """JWT authentication plugin"""

    configuration = Attribute("JWT configuration")
    enabled = Attribute("Enable JWT authentication?")

    audience = Attribute("Token audience")
    leeway = Attribute("Token leeway")
    http_header = Attribute("HTTP header used for JWT token")
    auth_type = Attribute("JWT authentication type")
    callback = Attribute("JWT authentication callback")
    json_encoder = Attribute("JSON encoder used to encode token claims")

    def create_token(self, principal, expiration=None, audience=None, **claims):
        """Create JWT token"""

    def get_claims(self, request):
        """Extract claims from JWT token"""

    def unauthenticated_userid(self, request):
        """User ID claimed by request credentials, if any"""
