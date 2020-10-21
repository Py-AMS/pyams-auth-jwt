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

This module is used for Pyramid integration
"""

import jwt

from pyams_auth_jwt.plugin import create_jwt_token, get_jwt_claims


__docformat__ = 'restructuredtext'


def include_package(config):
    """Pyramid package include"""

    # add translations
    config.add_translation_dirs('pyams_auth_jwt:locales')

    # add configuration directives
    config.add_request_method(create_jwt_token, 'create_jwt_token')
    config.add_request_method(get_jwt_claims, 'jwt_claims', reify=True)

    # add login route
    config.add_route('jwt_login', '/api/login/jwt')

    # update JWT algorithms
    try:
        import pycrypto  # pylint: disable=import-outside-toplevel,unused-import
    except ImportError:
        pass
    else:
        from jwt.contrib.algorithms.pycrypto import RSAAlgorithm
        jwt.unregister_algorithm('RS256')
        jwt.register_algorithm('RS256', RSAAlgorithm(RSAAlgorithm.SHA256))
        jwt.unregister_algorithm('RS512')
        jwt.register_algorithm('RS512', RSAAlgorithm(RSAAlgorithm.SHA512))

    try:
        import ecdsa  # pylint: disable=import-outside-toplevel,unused-import
    except ImportError:
        pass
    else:
        from jwt.contrib.algorithms.py_ecdsa import ECAlgorithm
        jwt.unregister_algorithm('ES256')
        jwt.register_algorithm('ES256', ECAlgorithm(ECAlgorithm.SHA256))
        jwt.unregister_algorithm('ES512')
        jwt.register_algorithm('ES512', ECAlgorithm(ECAlgorithm.SHA512))

    config.scan()
