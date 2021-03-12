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

"""PyAMS JWT authentication package.include module

This module is used for Pyramid integration.
"""

import jwt

from pyams_auth_jwt.interfaces import REST_TOKEN_ROUTE, REST_VERIFY_ROUTE
from pyams_auth_jwt.plugin import JWTTokenObjectPredicate, create_jwt_token, get_jwt_claims


__docformat__ = 'restructuredtext'


def include_package(config):
    """Pyramid package include"""

    # add translations
    config.add_translation_dirs('pyams_auth_jwt:locales')

    # add configuration directives
    config.add_request_method(create_jwt_token, 'create_jwt_token')
    config.add_request_method(get_jwt_claims, 'jwt_claims', reify=True)

    # add route predicate
    config.add_view_predicate('jwt_object', JWTTokenObjectPredicate)

    # register new REST API routes
    config.add_route(REST_TOKEN_ROUTE,
                     config.registry.settings.get('pyams.jwt.rest_token_route',
                                                  '/api/auth/jwt/token'))
    config.add_route(REST_VERIFY_ROUTE,
                     config.registry.settings.get('pyams.jwt.rest_verify_route',
                                                  '/api/auth/jwt/verify'))

    # update JWT algorithms
    try:
        import pycrypto  # pylint: disable=import-outside-toplevel,unused-import
    except ImportError:
        pass
    else:
        from jwt.contrib.algorithms.pycrypto import RSAAlgorithm  # pylint: disable=import-outside-toplevel
        jwt.unregister_algorithm('RS256')
        jwt.register_algorithm('RS256', RSAAlgorithm(RSAAlgorithm.SHA256))
        jwt.unregister_algorithm('RS512')
        jwt.register_algorithm('RS512', RSAAlgorithm(RSAAlgorithm.SHA512))

    try:
        import ecdsa  # pylint: disable=import-outside-toplevel,unused-import
    except ImportError:
        pass
    else:
        from jwt.contrib.algorithms.py_ecdsa import ECAlgorithm  # pylint: disable=import-outside-toplevel
        jwt.unregister_algorithm('ES256')
        jwt.register_algorithm('ES256', ECAlgorithm(ECAlgorithm.SHA256))
        jwt.unregister_algorithm('ES512')
        jwt.register_algorithm('ES512', ECAlgorithm(ECAlgorithm.SHA512))

    try:
        import pyams_zmi  # pylint: disable=import-outside-toplevel,unused-import
        config.scan()
    except ImportError:
        config.scan(ignore='pyams_auth_jwt.zmi')
