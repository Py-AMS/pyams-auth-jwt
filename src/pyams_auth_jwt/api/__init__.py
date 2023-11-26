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
from pyramid.authorization import Authenticated
from pyramid.httpexceptions import HTTPAccepted, HTTPBadRequest, HTTPForbidden, HTTPOk, HTTPServiceUnavailable, \
    HTTPUnauthorized

from pyams_auth_jwt.interfaces import ACCESS_OBJECT, IJWTProxyHandler, \
    IJWTSecurityConfiguration, REFRESH_OBJECT, REST_TOKEN_ROUTE, REST_VERIFY_ROUTE
from pyams_auth_jwt.plugin import create_jwt_token, get_jwt_claims as get_request_claims
from pyams_security.credential import Credentials
from pyams_security.interfaces import ISecurityManager
from pyams_security.rest import check_cors_origin, set_cors_headers
from pyams_utils.registry import query_utility
from pyams_utils.rest import BaseStatusSchema, PropertiesMapping, STATUS, http_error, rest_responses

__docformat__ = 'restructuredtext'


TEST_MODE = sys.argv[-1].endswith('/test')


class ClaimsInfo(MappingSchema):
    """Claims setter schema"""
    claims = SchemaNode(PropertiesMapping(),
                        description="Custom claims",
                        missing=drop)


class LoginInfo(ClaimsInfo):
    """Login schema"""
    login = SchemaNode(String(),
                       description="User login")
    password = SchemaNode(String(),
                          description="User password")


class TokensResult(BaseStatusSchema):
    """Tokens result schema"""
    accessToken = SchemaNode(String(),
                             description="Access token")
    refreshToken = SchemaNode(String(),
                              description="Refresh token")


class ClaimsObjectInfo(MappingSchema):
    """Claims object info"""
    obj = SchemaNode(String(),
                     description="Token object",
                     validator=OneOf((ACCESS_OBJECT, REFRESH_OBJECT)),
                     missing=drop)


class ClaimsElements(ClaimsObjectInfo):
    """Token claims elements schema"""
    sub = SchemaNode(String(),
                     description="Principal ID")
    iat = SchemaNode(Int(),
                     description="Token issue timestamp, in seconds")
    exp = SchemaNode(Int(),
                     description="Token expiration timestamp, in seconds")


#
# JWT token management service
#

jwt_token = Service(name=REST_TOKEN_ROUTE,
                    pyramid_route=REST_TOKEN_ROUTE,
                    description="JWT tokens management")


@jwt_token.options(validators=(check_cors_origin, set_cors_headers))
def jwt_token_options(request):  # pylint: disable=unused-argument
    """JWT token OPTIONS handler"""
    return ''


class JWTTokenPostResponse(MappingSchema):
    """Token post response"""

    body = TokensResult()


jwt_token_post_responses = rest_responses.copy()
jwt_token_post_responses[HTTPOk.code] = JWTTokenPostResponse(
    description="Get new access and refresh tokens matching credentials")


@jwt_token.post(require_csrf=False,
                content_type=('application/json', 'multipart/form-data'),
                schema=LoginInfo(),
                validators=(check_cors_origin, colander_body_validator, set_cors_headers),
                response_schemas=jwt_token_post_responses)
def get_jwt_token(request):
    """Get new access and refresh tokens matching credentials"""
    # check security manager utility
    sm = query_utility(ISecurityManager)  # pylint: disable=invalid-name
    if sm is None:
        return http_error(request, HTTPServiceUnavailable)
    configuration = IJWTSecurityConfiguration(sm)
    if not configuration.enabled:
        return http_error(request, HTTPServiceUnavailable)
    # check request params
    params = request.params if TEST_MODE else request.validated
    login = params.get('login')
    if not login:
        return http_error(request, HTTPBadRequest, 'missing credentials')
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
    if principal_id is None:
        return http_error(request, HTTPUnauthorized, "invalid credentials")
    custom_claims = params.get('claims', {})
    request.response.cache_expires(configuration.refresh_expiration)
    return {
        'status': STATUS.SUCCESS.value,
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


class JWTTokenGetResponse(MappingSchema):
    """Token claims getter response"""

    body = ClaimsElements()


jwt_token_get_responses = rest_responses.copy()
jwt_token_get_responses[HTTPOk.code] = JWTTokenGetResponse(
    description="Extract claims from provided token")


@jwt_token.get(content_type=('multipart/form-data', 'application/json'),
               schema=ClaimsObjectInfo(),
               validators=(check_cors_origin, colander_body_validator, set_cors_headers),
               response_schemas=jwt_token_get_responses)
def get_jwt_claims(request):
    """Extract claims from provided token"""
    sm = query_utility(ISecurityManager)  # pylint: disable=invalid-name
    if sm is None:
        return http_error(request, HTTPServiceUnavailable)
    configuration = IJWTSecurityConfiguration(sm)
    if not configuration.enabled:
        return http_error(request, HTTPServiceUnavailable)
    params = request.params if TEST_MODE else request.validated
    obj = params.get('obj')
    if configuration.proxy_mode:
        handler = IJWTProxyHandler(sm, None)
        if handler is not None:
            status_code, claims = handler.get_claims(request, obj)  # pylint: disable=assignment-from-no-return
            request.response.status_code = status_code
            return claims
    return get_request_claims(request, obj)


class JWTTokenPatchResponse(MappingSchema):
    """Token patch response"""

    body = TokensResult()


jwt_token_patch_responses = rest_responses.copy()
jwt_token_patch_responses[HTTPOk.code] = JWTTokenPatchResponse(
    description="Get new access token from valid refresh token")


@jwt_token.patch(require_csrf=False,
                 content_type=('multipart/form-data', 'application/json'),
                 jwt_object=REFRESH_OBJECT,
                 schema=ClaimsInfo(),
                 validators=(check_cors_origin, colander_body_validator, set_cors_headers),
                 response_schemas=jwt_token_patch_responses)
def refresh_jwt_token(request):
    """JWT token refresh service"""
    sm = query_utility(ISecurityManager)  # pylint: disable=invalid-name
    if sm is None:
        return http_error(request, HTTPServiceUnavailable)
    configuration = IJWTSecurityConfiguration(sm)
    if not configuration.enabled:
        return http_error(request, HTTPServiceUnavailable)
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
        return http_error(request, HTTPForbidden)
    principal_id = claims.get('sub')
    if not principal_id:
        return http_error(request, HTTPUnauthorized)
    params = request.params if TEST_MODE else request.validated
    custom_claims = params.get('claims', {})
    return {
        'status': STATUS.SUCCESS.value,
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


@jwt_verify.options(validators=(check_cors_origin, set_cors_headers))
def jwt_verify_options(request):  # pylint: disable=unused-argument
    """JWT token verification OPTIONS handler"""
    return ''


class JWTVerifyGetResponse(MappingSchema):
    """Token verification response"""

    body = TokensResult()


jwt_verify_get_responses = rest_responses.copy()
jwt_verify_get_responses[HTTPOk.code] = JWTVerifyGetResponse(
    description="Get JWT token for authenticated principal")


@jwt_verify.get(schema=ClaimsObjectInfo(),
                validators=(check_cors_origin, set_cors_headers),
                response_schemas=jwt_verify_get_responses)
def get_current_jwt_token(request):
    """Get JWT token for authenticated principal"""
    identity = request.identity
    if identity is None:
        return http_error(request, HTTPUnauthorized)
    if Authenticated not in identity.principals:
        return http_error(request, HTTPForbidden)
    manager = query_utility(ISecurityManager)
    if manager is None:
        return http_error(request, HTTPServiceUnavailable)
    configuration = IJWTSecurityConfiguration(manager)
    if not configuration.enabled:
        return http_error(request, HTTPServiceUnavailable)
    custom_claims = request.params.get('claims', {})
    request.response.cache_expires(configuration.refresh_expiration)
    return {
        'status': STATUS.SUCCESS.value,
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


class JWTVerifyPostResponse(MappingSchema):
    """JWT token verification response"""

    body = BaseStatusSchema()


jwt_verify_post_responses = rest_responses.copy()
jwt_verify_post_responses[HTTPOk.code] = JWTVerifyPostResponse(
    description="Verify JWT access token")


@jwt_verify.post(require_csrf=False,
                 jwt_object=ACCESS_OBJECT,
                 schema=ClaimsObjectInfo(),
                 validators=(check_cors_origin, colander_body_validator, set_cors_headers),
                 response_schemas=jwt_verify_post_responses)
def verify_jwt_token(request):
    """Verify JWT access token"""
    manager = query_utility(ISecurityManager)
    if manager is None:
        return http_error(request, HTTPServiceUnavailable)
    configuration = IJWTSecurityConfiguration(manager)
    if not configuration.enabled:
        return http_error(request, HTTPServiceUnavailable)
    claims = get_jwt_claims(request)
    if not claims:
        return http_error(request, HTTPForbidden)
    request.response.status_code = HTTPAccepted.code
    return {
        'status': STATUS.SUCCESS.value
    }
