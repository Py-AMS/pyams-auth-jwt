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

from zope.annotation.interfaces import IAttributeAnnotatable
from zope.container.interfaces import IContainer
from zope.interface import Attribute, Interface, Invalid, invariant
from zope.schema import Bool, Choice, Datetime, Int, Text, TextLine

from pyams_security.interfaces.plugin import IAuthenticationPlugin, ICredentialsPlugin, IDirectoryPlugin
from pyams_security.schema import PrincipalField
from pyams_utils.cache import BEAKER_CACHES_VOCABULARY
from pyams_utils.schema import HTTPMethodField, TextLineListField

__docformat__ = 'restructuredtext'

from pyams_auth_jwt import _


#
# API endpoints
#

REST_TOKEN_ROUTE = 'pyams_auth_jwt.rest.token'
'''REST JWT token API route name'''

REST_TOKEN_PATH = '/api/auth/jwt/token'
'''REST JWT token API default path'''

REST_VERIFY_ROUTE = 'pyams_auth_jwt.rest.verify'
'''REST JWT verify API route name'''

REST_VERIFY_PATH = '/api/auth/jwt/verify'
'''REST JWT verify API default path'''


#
# JWT authentication utility interface
#

JWT_PREFIX = 'jwt'
"""JWT plugin prefix"""

JWT_CLIENT_CONTAINER_KEY = 'pyams_auth_jwt.client_keys'
"""JWT client keys container annotations key"""

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


class IJWTClientKey(Interface):
    """JWT client key information"""
    
    key_id = TextLine(title=_("Key ID"),
                      description=_("This ID must be unique between all JWT client keys, and provided as "
                                    "'kid' tokens header"),
                      required=True)
    
    enabled = Bool(title=_("Enabled client key?"),
                   description=_("Select 'no' to disable this client key temporarily"),
                   required=True,
                   default=True)

    label = TextLine(title=_("Client key label"),
                     description=_("This label will be used to identify the client key"),
                     required=True)

    issuer = TextLine(title=_("Issuer"),
                      description=_("JWT tokens matching this client_key will be accepted only if their issuer "
                                    "('iss' claim) is matching this value"),
                      required=True)
    
    audience = TextLine(title=_("Audience"),
                        description=_("JWT tokens matching this client key will be accepted only if their audience "
                                      "('aud' claim) is matching this value"),
                        required=True)

    public_key = Text(title=_("Client public key"),
                      description=_("The public key is required when using RS* algorithm"),
                      required=True)

    algorithm = Choice(title=_("JWT encoding algorithm"),
                       description=_("Protocol used by the client key"),
                       required=True,
                       values=('ES256', 'ES384', 'ES512',
                               'RS256', 'RS384', 'RS512'),
                       default='ES512')

    principal_id = PrincipalField(title=_("Associated principal"),
                                  description=_("If defined, this will identify the principal which will be used "
                                                "when a request will be authenticated with this JWT client key"),
                                  required=False)
    
    @invariant
    def check_principal_id(self):
        """Check principal ID"""
        if self.principal_id and self.principal_id.startswith(f'{JWT_PREFIX}:'):
            raise Invalid(_("Selected principal can't be another JWT client key!"))
        
    def get_principal(self, request=None):
        """Get principal matching this JWT client key"""
        
    activation_date = Datetime(title=_("Activation date"),
                               description=_("This JWT client key will be enabled only after this date"),
                               required=False)
    
    expiration_date = Datetime(title=_("Expiration date"),
                               description=_("This JWT client key will not be enabled after this date"),
                               required=False)

    restrict_referrers = Bool(title=_("Restrict referrers"),
                              description=_("If this option is enabled, only selected referrers will be enabled"),
                              required=True,
                              default=False)

    allowed_referrers = TextLineListField(title=_("Allowed referrers"),
                                          description=_("Only selected referrers will be allowed to use this "
                                                        "client key"),
                                          required=False)

    active = Attribute("Client key activity checker")
    
    
class IJWTClientKeyContainer(IContainer):
    """JWT client key container"""
    
    def update_key(self, key, old_principal_id, new_principal_id):
        """Update key principal"""
    
    
class IJWTSecurityConfiguration(IAttributeAnnotatable):
    """Security manager configuration interface for JWT"""

    audience = TextLine(title=_("Audience"),
                        description=_("Audience defines the target of JWT tokens"),
                        required=False)
    
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
                       description=_("HS* protocols are using a shared secret, RS* protocols "
                                     "are using RSA keys and ES* protocols are using ECDSA keys; "
                                     "ES* protocols are as safe as RS* protocols but quicker than "
                                     "RS* protocols for the same hash length"),
                       required=False,
                       values=('ES256', 'ES384', 'ES512',
                               'RS256', 'RS384', 'RS512',
                               'HS256', 'HS384', 'HS512'),
                       default='ES512')

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
                                        default=('POST', REST_TOKEN_PATH))

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
                                         default=('GET', REST_TOKEN_PATH))

    refresh_token_service = HTTPMethodField(title=_("Token refresh service"),
                                            description=_("REST HTTP service used to get a new "
                                                          "access token with a refresh token"),
                                            required=False,
                                            default=('PATCH', REST_TOKEN_PATH))

    verify_token_service = HTTPMethodField(title=_("Token verify service"),
                                           description=_("REST HTTP service used to check "
                                                         "validity of an existing token"),
                                           required=False,
                                           default=('POST', REST_VERIFY_PATH))

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
                    raise Invalid(_("You must define JWT secret to use HS* algorithms"))
            else:
                if not (self.private_key and self.public_key):
                    raise Invalid(_("You must define a private and a public key to use "
                                    "RS* or ES* algorithms"))
        if self.proxy_mode:
            if not self.authority:
                raise Invalid(_("You must define authentication authority to use proxy mode"))
            if self.use_cache and not self.selected_cache:
                raise Invalid(_("You must choose a cache to enable tokens caching"))


class IJWTAuthenticationPlugin(ICredentialsPlugin, IAuthenticationPlugin, IDirectoryPlugin):
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
