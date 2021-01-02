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

"""PyAMS_auth_jwt.proxy module

This module defines a proxy handler, which is used when the JWT authentication plug-in
is configured in proxy mode, relying on another authentication authority providing it's
own REST API.
"""

import logging

import requests
from pyramid.httpexceptions import HTTPOk, HTTPUnauthorized

from pyams_auth_jwt.interfaces import IJWTAuthenticationPlugin, IJWTProxyHandler, \
    IJWTSecurityConfiguration, JWT_PROXY_CACHE_NAME, JWT_PROXY_TOKENS_NAMESPACE
from pyams_security.interfaces import ISecurityManager
from pyams_utils.adapter import ContextAdapter, adapter_config
from pyams_utils.cache import get_cache


__docformat__ = 'restructuredtext'


LOGGER = logging.getLogger('PyAMS (JWT security)')


@adapter_config(required=IJWTAuthenticationPlugin,
                provides=IJWTProxyHandler)
@adapter_config(required=ISecurityManager,
                provides=IJWTProxyHandler)
class JWTProxyHandler(ContextAdapter):
    """JWT proxy handler"""

    def get_claims(self, request, obj=None):
        """Get claims from provided request authorization"""
        authorization = getattr(request, 'authorization', None)
        if authorization is None:
            authorization = request.headers.get('Authorization')
        else:
            authorization = ' '.join(authorization)
        if not authorization:
            return HTTPUnauthorized.code, {}
        configuration = IJWTSecurityConfiguration(self.context)

        # Check Beaker cache
        tokens_cache = None
        cache_key = None
        if configuration.use_cache:
            cache_key = authorization
            if obj:
                cache_key = '{}::{}'.format(cache_key, obj)
            tokens_cache = get_cache(JWT_PROXY_CACHE_NAME, configuration.selected_cache,
                                     JWT_PROXY_TOKENS_NAMESPACE)
            try:
                claims = tokens_cache.get_value(cache_key)
            except KeyError:
                pass
            else:
                return HTTPOk.code, claims

        # Call authority REST API
        method, service = configuration.get_claims_service  # pylint: disable=unpacking-non-sequence
        rest_service = '{}{}'.format(configuration.authority, service)
        params = {}
        data = {}
        if obj:
            if method == 'GET':
                params['obj'] = obj
            else:
                data['obj'] = obj
        rest_request = requests.request(method, rest_service,
                                        params=params, data=data,
                                        headers={'Authorization': authorization})
        status_code = rest_request.status_code
        if status_code == requests.codes.ok:  # pylint: disable=no-member
            claims = rest_request.json()
            if tokens_cache is not None:
                tokens_cache.set_value(cache_key, claims)
            return status_code, claims
        return status_code, {}

    def get_tokens(self, request, credentials):  # pylint: disable=unused-argument
        """Get new tokens from authentication authority"""
        configuration = IJWTSecurityConfiguration(self.context)
        method, service = configuration.get_token_service  # pylint: disable=unpacking-non-sequence
        rest_service = '{}{}'.format(configuration.authority, service)
        if method == 'GET':
            rest_request = requests.request(method, rest_service,
                                            params=credentials.attributes,
                                            allow_redirects=False,
                                            verify=configuration.verify_ssl)
        else:
            rest_request = requests.request(method, rest_service,
                                            data=credentials.attributes,
                                            allow_redirects=False,
                                            verify=configuration.verify_ssl)
        status_code = rest_request.status_code
        if status_code == requests.codes.ok:  # pylint: disable=no-member
            result = rest_request.json()
            result[configuration.access_token_name] = \
                result.pop(configuration.proxy_access_token_name)
            result[configuration.refresh_token_name] = \
                result.pop(configuration.proxy_refresh_token_name)
            return status_code, result
        return status_code, {}

    def refresh_token(self, request):
        """Get new access token with refresh token authorization"""
        configuration = IJWTSecurityConfiguration(self.context)
        method, service = configuration.refresh_token_service  # pylint: disable=unpacking-non-sequence
        rest_service = '{}{}'.format(configuration.authority, service)
        rest_request = requests.request(method, rest_service, headers={
            'Authorization': request.headers.get('Authorization')
        })
        status_code = rest_request.status_code
        if status_code == requests.codes.ok:  # pylint: disable=no-member
            result = rest_request.json()
            result[configuration.access_token_name] = \
                result.pop(configuration.proxy_access_token_name)
            return status_code, result
        return status_code, {}
