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

"""PyAMS_auth_jwt.zmi.plugin module

This module is used to register ZMI views used to manage JWT configuration.
"""

from zope.interface import Interface

from pyams_auth_jwt.interfaces import IJWTSecurityConfiguration
from pyams_form.ajax import ajax_form_config
from pyams_form.field import Fields
from pyams_form.interfaces.form import IGroup
from pyams_layer.interfaces import IPyAMSLayer
from pyams_security.interfaces import ISecurityManager
from pyams_security.interfaces.base import MANAGE_SECURITY_PERMISSION
from pyams_security_views.zmi import ISecurityMenu
from pyams_site.interfaces import ISiteRoot
from pyams_skin.interfaces.viewlet import IHeaderViewletManager
from pyams_skin.viewlet.help import AlertMessage
from pyams_utils.adapter import adapter_config
from pyams_utils.registry import get_utility
from pyams_viewlet.viewlet import viewlet_config
from pyams_zmi.form import AdminEditForm, FormGroupChecker
from pyams_zmi.interfaces import IAdminLayer
from pyams_zmi.zmi.viewlet.menu import NavigationMenuItem


__docformat__ = 'restructuredtext'

from pyams_auth_jwt import _  # pylint: disable=ungrouped-imports


@viewlet_config(name='jwt-security-configuration.menu',
                context=ISiteRoot, layer=IAdminLayer,
                manager=ISecurityMenu, weight=50,
                permission=MANAGE_SECURITY_PERMISSION)
class JWTSecurityConfiguration(NavigationMenuItem):
    """JWT security configuration menu"""

    label = _("JWT configuration")
    href = '#jwt-security-configuration.html'


@ajax_form_config(name='jwt-security-configuration.html', context=ISiteRoot, layer=IPyAMSLayer,
                  permission=MANAGE_SECURITY_PERMISSION)
class JWTSecurityConfigurationEditForm(AdminEditForm):
    """JWT security configuration edit form"""

    title = _("Security manager")
    legend = _("JWT configuration")

    fields = Fields(Interface)


@adapter_config(name='jwt-configuration',
                required=(ISiteRoot, IAdminLayer, JWTSecurityConfigurationEditForm),
                provides=IGroup)
class JWTConfigurationGroup(FormGroupChecker):
    """JWT configuration edit group"""

    fields = Fields(IJWTSecurityConfiguration)

    def get_content(self):
        sm = get_utility(ISecurityManager)  # pylint: disable=invalid-name
        return IJWTSecurityConfiguration(sm)

    def update_widgets(self, prefix=None):
        super(JWTConfigurationGroup, self).update_widgets(prefix)
        widget = self.widgets.get('private_key')
        if widget is not None:
            widget.prefix = JWTConfigurationKeyAlert(self.context, self.request, self, None)
            widget.rows = 15
            widget.add_class('monospace')
        widget = self.widgets.get('public_key')
        if widget is not None:
            widget.rows = 5
            widget.add_class('monospace')


@viewlet_config(name='jwt-configuration.header',
                context=ISiteRoot, layer=IAdminLayer, view=JWTConfigurationGroup,
                manager=IHeaderViewletManager, weight=1)
class JWTConfigurationHeader(AlertMessage):
    """JWT configuration header"""

    status = 'info'

    _message = _("""JWT authentication module provides features and a REST API which can be \
used to generate, refresh and verify access tokens.
You can choose to use a simple secret key to encrypt your tokens, or to use a \
private and a public keys (which can to be used to share tokens between two \
applications)
""")


class JWTConfigurationKeyAlert(AlertMessage):
    """JWT configuration keys alert"""

    status = 'info'
    css_class = 'mb-1 p-2'

    _message = _("""You can use the `openssl` command to generate your keys:

    openssl genpkey -algorithm RSA -out private-key.pem
    openssl rsa -pubout -in private-key.pem -out public-key.pem
""")
    message_renderer = 'markdown'
