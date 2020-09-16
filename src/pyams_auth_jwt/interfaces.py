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

This module provides custom package interfaces
"""

from zope.interface import Attribute, Interface, invariant
from zope.interface.interfaces import Invalid
from zope.schema import Bool, Choice, Int, Text, TextLine

from pyams_security.interfaces import IAuthenticationPlugin


__docformat__ = 'restructuredtext'

from pyams_auth_jwt import _


#
# JWT authentication utility interface
#

class IJWTSecurityConfiguration(Interface):
    """Security manager configuration interface for JWT"""

    enabled = Bool(title=_("Enable JWT login?"),
                   description=_("Enable login via JWT authentication"),
                   required=False,
                   default=False)

    use_cookie = Bool(title=_("Send cookie?"),
                      description=_("If 'yes', a session cookie will be sent on authentication"),
                      required=False,
                      default=False)

    algorithm = Choice(title=_("JWT encoding algorithm"),
                       description=_(""),
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

    expiration = Int(title=_("Token lifetime"),
                     description=_("JWT token lifetime, in seconds"),
                     required=False)

    @invariant
    def check_configuration(self):
        """Check for JWT configuration"""
        if self.enabled:
            if not self.algorithm:
                raise Invalid(_("You must choose an algorithm to enable JWT authentication"))
            if self.algorithm.startswith('HS'):  # pylint: disable=no-member
                if not self.secret:
                    raise Invalid(_("You must define JWT secret to use HS256 algorithm"))
            elif self.algorithm.startswith('RS'):  # pylint: disable=no-member
                if not (self.private_key and self.public_key):
                    raise Invalid(_("You must define a private and a public key to use RS256 "
                                    "algorithm"))


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
