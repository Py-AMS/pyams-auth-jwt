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

import sys

from colander import Int, MappingSchema, OneOf, SchemaNode, String, drop
from cornice import Service
from cornice.validators import colander_body_validator
from pyramid.httpexceptions import HTTPAccepted, HTTPBadRequest, HTTPForbidden, \
    HTTPNotFound, HTTPOk, HTTPServiceUnavailable, HTTPUnauthorized
from pyramid.security import Authenticated

from pyams_auth_jwt.interfaces import ACCESS_OBJECT, IJWTProxyHandler, \
    IJWTSecurityConfiguration, REFRESH_OBJECT, REST_TOKEN_ROUTE, REST_VERIFY_ROUTE
from pyams_auth_jwt.plugin import create_jwt_token, get_jwt_claims as get_request_claims
from pyams_security.credential import Credentials
from pyams_security.interfaces import ISecurityManager
from pyams_utils.registry import query_utility
from pyams_utils.rest import PropertiesMapping


__docformat__ = 'restructuredtext'

from pyams_auth_jwt import _  # pylint: disable=ungrouped-imports


TEST_MODE = sys.argv[-1].endswith('/test')


class ErrorSchema(MappingSchema):
    """Base error schema"""
    status = SchemaNode(String(),
                        title=_("Response status"))
    message = SchemaNode(String(),
                         title=_("Error message"),
                         missing=drop)


class ClaimsSetterSchema(MappingSchema):
    """Claims setter schema"""
    claims = SchemaNode(PropertiesMapping(),
                        title=_("Custom claims"),
                        missing=drop)


class LoginSchema(ClaimsSetterSchema):
    """Login schema"""
    login = SchemaNode(String(),
                       title=_("Login"))
    password = SchemaNode(String(),
                          title=_("Password"))


class StatusSchema(MappingSchema):
    """Base status response schema"""
    status = SchemaNode(String(),
                        title=_("Response status"),
                        validator=OneOf(('success', 'error')))


class TokensSchema(StatusSchema):
    """Tokens response schema"""
    accessToken = SchemaNode(String(),
                             title=_("Access token"))
    refreshToken = SchemaNode(String(),
                              title=_("Refresh token"))


class ClaimsObjectSchema(MappingSchema):
    """Claims getter schema"""
    obj = SchemaNode(String(),
                     title=_("Token object"),
                     validator=OneOf((ACCESS_OBJECT, REFRESH_OBJECT)),
                     missing=drop)


class ClaimsSchema(ClaimsObjectSchema):
    """Token claims schema"""
    sub = SchemaNode(String(),
                     title=_("Principal ID"))
    iat = SchemaNode(Int(),
                     title=_("Token issue timestamp, in seconds"))
    exp = SchemaNode(Int(),
                     title=_("Token expiration timestamp, in seconds"))


jwt_responses = {
    HTTPOk.code: TokensSchema(description=_("Tokens properties")),
    HTTPAccepted.code: StatusSchema(description=_("Token accepted")),
    HTTPNotFound.code: ErrorSchema(description=_("Page not found")),
    HTTPUnauthorized.code: ErrorSchema(description=_("Unauthorized")),
    HTTPForbidden.code: ErrorSchema(description=_("Forbidden access")),
    HTTPBadRequest.code: ErrorSchema(description=_("Missing arguments")),
    HTTPServiceUnavailable.code: ErrorSchema(description=_("Service unavailable"))
}

if TEST_MODE:
    service_params = {}
else:
    service_params = {
        'response_schemas': jwt_responses
    }


jwt_token = Service(name=REST_TOKEN_ROUTE,
                    pyramid_route=REST_TOKEN_ROUTE,
                    description="JWT tokens management")


@jwt_token.post(require_csrf=False,
                content_type=('application/json', 'multipart/form-data'),
                schema=LoginSchema(),
                validators=(colander_body_validator,),
                **service_params)
def get_jwt_token(request):
    """REST login endpoint for JWT authentication"""
    # check security manager utility
    sm = query_utility(ISecurityManager)  # pylint: disable=invalid-name
    if sm is None:
        raise HTTPServiceUnavailable()
    configuration = IJWTSecurityConfiguration(sm)
    if not configuration.enabled:
        raise HTTPServiceUnavailable()
    # check request params
    params = request.params if TEST_MODE else request.validated
    login = params.get('login')
    if not login:
        raise HTTPBadRequest()
    credentials = Credentials('jwt', id=login, **params)
    # use remote authentication authority
    if configuration.proxy_mode:
        handler = IJWTProxyHandler(sm, None)
        if handler is not None:
            status_code, tokens = handler.get_tokens(request, credentials)  # pylint: disable=assignment-from-no-return
            request.response.status_code = status_code
            return tokens
    # authenticate principal in security manager
    principal_id = sm.authenticate(credentials, request)
    if principal_id is not None:
        custom_claims = params.get('claims', {})
        request.response.cache_expires(configuration.refresh_expiration)
        return {
            'status': 'success',
            configuration.access_token_name:
                create_jwt_token(request,
                                 principal_id,
                                 expiration=configuration.access_expiration,
                                 obj=ACCESS_OBJECT,
                                 **custom_claims),
            configuration.refresh_token_name:
                create_jwt_token(request,
                                 principal_id,
                                 expiration=configuration.refresh_expiration,
                                 obj=REFRESH_OBJECT)
        }
    request.response.status_code = HTTPUnauthorized.code
    return {
        'status': 'error',
        'message': request.localizer.translate(_("Invalid credentials!"))
    }


@jwt_token.get(require_csrf=False,
               content_type=('multipart/form-data', 'application/json'),
               schema=ClaimsObjectSchema(),
               validators=(colander_body_validator,),
               **service_params)
def get_jwt_claims(request):
    """Extract claims from provided JWT token"""
    sm = query_utility(ISecurityManager)  # pylint: disable=invalid-name
    if sm is None:
        raise HTTPServiceUnavailable()
    configuration = IJWTSecurityConfiguration(sm)
    if not configuration.enabled:
        raise HTTPServiceUnavailable()
    params = request.params if TEST_MODE else request.validated
    obj = params.get('obj')
    if configuration.proxy_mode:
        handler = IJWTProxyHandler(sm, None)
        if handler is not None:
            status_code, claims = handler.get_claims(request, obj)  # pylint: disable=assignment-from-no-return
            request.response.status_code = status_code
            return claims
    return get_request_claims(request, obj)


@jwt_token.patch(require_csrf=False,
                 content_type=('multipart/form-data', 'application/json'),
                 jwt_object=REFRESH_OBJECT,
                 schema=ClaimsSetterSchema(),
                 validators=(colander_body_validator,),
                 **service_params)
def refresh_jwt_token(request):
    """JWT token refresh service"""
    sm = query_utility(ISecurityManager)  # pylint: disable=invalid-name
    if sm is None:
        raise HTTPServiceUnavailable()
    configuration = IJWTSecurityConfiguration(sm)
    if not configuration.enabled:
        raise HTTPServiceUnavailable()
    # user remote authentication authority
    if configuration.proxy_mode:
        handler = IJWTProxyHandler(sm, None)
        if handler is not None:
            status_code, token = handler.refresh_token(request)  # pylint: disable=assignment-from-no-return
            request.response.status_code = status_code
            return token
    # refresh token locally
    claims = get_jwt_claims(request)
    if not claims:
        raise HTTPForbidden()
    principal_id = claims.get('sub')
    if not principal_id:
        raise HTTPUnauthorized()
    params = request.params if TEST_MODE else request.validated
    custom_claims = params.get('claims', {})
    return {
        'status': 'success',
        configuration.access_token_name:
            create_jwt_token(request,
                             principal_id,
                             expiration=configuration.access_expiration,
                             obj=ACCESS_OBJECT,
                             **custom_claims)
    }


jwt_verify = Service(name=REST_VERIFY_ROUTE,
                     pyramid_route=REST_VERIFY_ROUTE,
                     description="JWT tokens verification")


@jwt_verify.get(require_csrf=False,
                schema=ClaimsObjectSchema(),
                **service_params)
def get_current_jwt_token(request):
    """Get current JWT token for authenticated principal"""
    manager = query_utility(ISecurityManager)
    if manager is None:
        raise HTTPServiceUnavailable()
    configuration = IJWTSecurityConfiguration(manager)
    if not configuration.enabled:
        raise HTTPServiceUnavailable()
    if Authenticated not in request.effective_principals:
        raise HTTPForbidden()
    custom_claims = request.params.get('claims', {})
    request.response.cache_expires(configuration.refresh_expiration)
    return {
        'status': 'success',
        configuration.access_token_name:
            create_jwt_token(request,
                             request.authenticated_userid,
                             expiration=configuration.access_expiration,
                             obj=ACCESS_OBJECT,
                             **custom_claims),
        configuration.refresh_token_name:
            create_jwt_token(request,
                             request.authenticated_userid,
                             expiration=configuration.refresh_expiration,
                             obj=REFRESH_OBJECT)
    }


@jwt_verify.post(require_csrf=False,
                 jwt_object=ACCESS_OBJECT,
                 schema=ClaimsObjectSchema(),
                 validators=(colander_body_validator,),
                 **service_params)
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
        raise HTTPForbidden()
    request.response.status_code = HTTPAccepted.code
    return {
        'status': 'success'
    }
