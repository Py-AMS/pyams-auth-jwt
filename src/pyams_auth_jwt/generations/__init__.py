# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#

from importlib import import_module

from pyams_site.interfaces import ISiteGenerations
from pyams_utils.registry import utility_config

__docformat__ = 'restructuredtext'


@utility_config(name='PyAMS auth JWT', provides=ISiteGenerations)
class WebsiteGenerationsChecker:
    """PyAMS JWT authentication package generations checker"""

    order = 200
    generation = 2

    def evolve(self, site, current=None):
        """Check for required utilities, tables and tools"""
        if not current:
            current = 1
        for generation in range(current, self.generation):
            module_name = f'pyams_auth_jwt.generations.evolve{generation}'
            module = import_module(module_name)
            module.evolve(site)
