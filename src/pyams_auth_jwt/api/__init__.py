#
# Copyright (c) 2015-2020 Thierry Florac <tflorac AT ulthar.net>
# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#

"""PyAMS_auth_jwt.api module

This modules is used to register REST API to generate, check and refresh JWT tokens.
"""

from cornice import Service
from pyramid.httpexceptions import HTTPAccepted, HTTPBadRequest, HTTPForbidden, \
    HTTPServiceUnavailable, HTTPUnauthorized

from pyams_auth_jwt.interfaces import ACCESS_OBJECT, IJWTSecurityConfiguration, REFRESH_OBJECT
from pyams_auth_jwt.plugin import create_jwt_token, get_jwt_claims
from pyams_security.credential import Credentials
from pyams_security.interfaces import ISecurityManager
from pyams_utils.registry import query_utility


__docformat__ = 'restructuredtext'

from pyams_auth_jwt import _  # pylint: disable=ungrouped-imports


jwt_token = Service(name='jwt_token',
                    path='/api/auth/jwt/token',
                    description="JWT tokens management")


@jwt_token.post(require_csrf=False)
def get_jwt_token(request):
    """AJAX login view for JWT authentication"""
    # check security manager utility
    manager = query_utility(ISecurityManager)
    if manager is None:
        raise HTTPServiceUnavailable()
    configuration = IJWTSecurityConfiguration(manager)
    if not configuration.enabled:
        raise HTTPServiceUnavailable()
    params = request.params
    login = params.get('login')
    if not login:
        raise HTTPBadRequest()
    credentials = Credentials('jwt', id=login, **params)
    # authenticate principal in security manager
    principal_id = manager.authenticate(credentials, request)
    if principal_id is not None:
        return {
            'status': 'success',
            'accessToken': create_jwt_token(request,
                                            principal_id,
                                            expiration=configuration.access_expiration,
                                            obj=ACCESS_OBJECT),
            'refreshToken': create_jwt_token(request,
                                             principal_id,
                                             expiration=configuration.refresh_expiration,
                                             obj=REFRESH_OBJECT)
        }
    request.response.status_code = HTTPUnauthorized.code
    return {
        'status': 'error',
        'message': request.localizer.translate(_("Invalid credentials!"))
    }


@jwt_token.patch(require_csrf=False, jwt_object=REFRESH_OBJECT)
def refresh_jwt_token(request):
    """JWT token refresh view"""
    manager = query_utility(ISecurityManager)
    if manager is None:
        raise HTTPServiceUnavailable()
    configuration = IJWTSecurityConfiguration(manager)
    if not configuration.enabled:
        raise HTTPServiceUnavailable()
    claims = get_jwt_claims(request)
    if not claims:
        raise HTTPForbidden()
    principal_id = claims.get('sub')
    if not principal_id:
        raise HTTPUnauthorized()
    return {
        'status': 'success',
        'accessToken': create_jwt_token(request,
                                        principal_id,
                                        expiration=configuration.access_expiration,
                                        obj=ACCESS_OBJECT)
    }


jwt_verify = Service(name='jwt_verify',
                     path='/api/auth/jwt/verify',
                     description="JWT tokens verification")


@jwt_verify.post(require_csrf=False, jwt_object=ACCESS_OBJECT)
def verify_jwt_token(request):
    """JWT token verification view"""
    manager = query_utility(ISecurityManager)
    if manager is None:
        raise HTTPServiceUnavailable()
    configuration = IJWTSecurityConfiguration(manager)
    if not configuration.enabled:
        raise HTTPServiceUnavailable()
    claims = get_jwt_claims(request)
    if not claims:
        raise HTTPUnauthorized()
    request.response.status_code = HTTPAccepted.code
    return {
        'status': 'success'
    }