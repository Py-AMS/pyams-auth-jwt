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

"""PyAMS_*** module

"""

from pyramid.httpexceptions import HTTPNotFound
from pyramid.view import view_config

from pyams_auth_jwt.interfaces import IJWTSecurityConfiguration
from pyams_security.credential import Credentials
from pyams_security.interfaces import ISecurityManager
from pyams_utils.registry import query_utility


__docformat__ = 'restructuredtext'

from pyams_auth_jwt import _  # pylint: disable=ungrouped-imports


@view_config(route_name='jwt_login', renderer='json', xhr=True, request_method='POST')
def login(request):
    """AJAX login view for JWT authentication"""
    # check security manager utility
    manager = query_utility(ISecurityManager)
    if manager is None:
        raise HTTPNotFound()
    configuration = IJWTSecurityConfiguration(manager)
    if not configuration.enabled:
        raise HTTPNotFound()
    params = request.params
    credentials = Credentials('jwt', id=params.get('login'), **params)
    # authenticate principal in security manager
    principal_id = manager.authenticate(credentials, request)
    if principal_id is not None:
        return {
            'status': 'success',
            'token': request.create_jwt_token(principal_id)
        }
    return {
        'status': 'error',
        'message': request.localizer.translate(_("Invalid credentials!"))
    }
