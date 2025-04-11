# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#

from pyams_auth_jwt.interfaces import IJWTSecurityConfiguration
from pyams_security.interfaces import ISecurityManager
from pyams_utils.registry import get_local_registry, get_utility, set_local_registry

__docformat__ = 'restructuredtext'


def evolve(site):
    """Update JWT security configuration parent"""
    old_registry = get_local_registry()
    try:
        registry = site.getSiteManager()
        set_local_registry(registry)
        sm = get_utility(ISecurityManager)
        configuration = IJWTSecurityConfiguration(sm, None)
        if configuration is not None:
            configuration.__name__ = '++jwt++'
    finally:
        set_local_registry(old_registry)
        