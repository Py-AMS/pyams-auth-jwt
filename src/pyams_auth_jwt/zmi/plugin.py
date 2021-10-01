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

from pyams_auth_jwt.interfaces import IJWTSecurityConfiguration, JWT_PROXY_CACHE_NAME, \
    JWT_PROXY_TOKENS_NAMESPACE
from pyams_form.ajax import ajax_form_config
from pyams_form.browser.checkbox import SingleCheckBoxFieldWidget
from pyams_form.field import Fields
from pyams_form.interfaces.form import IGroup
from pyams_layer.interfaces import IPyAMSLayer
from pyams_security.interfaces import ISecurityManager
from pyams_security.interfaces.base import MANAGE_SECURITY_PERMISSION
from pyams_security_views.zmi import ISecurityMenu
from pyams_skin.interfaces.viewlet import IHeaderViewletManager
from pyams_skin.viewlet.help import AlertMessage
from pyams_utils.adapter import adapter_config
from pyams_utils.cache import clear_cache
from pyams_viewlet.viewlet import viewlet_config
from pyams_zmi.form import AdminEditForm, FormGroupChecker
from pyams_zmi.interfaces import IAdminLayer
from pyams_zmi.zmi.viewlet.menu import NavigationMenuItem


__docformat__ = 'restructuredtext'

from pyams_auth_jwt import _  # pylint: disable=ungrouped-imports


@viewlet_config(name='jwt-security-configuration.menu',
                context=ISecurityManager, layer=IAdminLayer,
                manager=ISecurityMenu, weight=50,
                permission=MANAGE_SECURITY_PERMISSION)
class JWTSecurityConfiguration(NavigationMenuItem):
    """JWT security configuration menu"""

    label = _("JWT configuration")
    href = '#jwt-security-configuration.html'


@ajax_form_config(name='jwt-security-configuration.html',
                  context=ISecurityManager, layer=IPyAMSLayer,
                  permission=MANAGE_SECURITY_PERMISSION)
class JWTSecurityConfigurationEditForm(AdminEditForm):
    """JWT security configuration edit form"""

    title = _("Security manager")
    legend = _("JWT configuration")

    fields = Fields(IJWTSecurityConfiguration).select('access_token_name', 'refresh_token_name')

    def get_content(self):
        return IJWTSecurityConfiguration(self.context)

    def apply_changes(self, data):
        configuration = self.get_content()
        old_region = configuration.selected_cache
        changes = super(JWTSecurityConfigurationEditForm, self).apply_changes(data)
        if changes and (old_region is not None):
            clear_cache(JWT_PROXY_CACHE_NAME, old_region, JWT_PROXY_TOKENS_NAMESPACE)
        return changes


@adapter_config(name='jwt-configuration',
                required=(ISecurityManager, IAdminLayer, JWTSecurityConfigurationEditForm),
                provides=IGroup)
class JWTConfigurationGroup(FormGroupChecker):
    """JWT configuration edit group"""

    fields = Fields(IJWTSecurityConfiguration).select('local_mode', 'algorithm', 'secret',
                                                      'private_key', 'public_key',
                                                      'access_expiration', 'refresh_expiration')
    weight = 10

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
                context=ISecurityManager, layer=IAdminLayer, view=JWTConfigurationGroup,
                manager=IHeaderViewletManager, weight=1)
class JWTConfigurationHeader(AlertMessage):
    """JWT configuration header"""

    status = 'info'

    _message = _("JWT authentication module \"local mode\" allows to generate, check and refresh "
                 "tokens locally.\n"
                 "You can choose to use a simple secret key to encrypt your tokens, or to "
                 "use a private and public keys pair (which can to be used to share tokens "
                 "between two applications).")


class JWTConfigurationKeyAlert(AlertMessage):
    """JWT configuration keys alert"""

    status = 'info'
    css_class = 'mb-1 p-2'

    _message = _("""You can use the `openssl` command to generate your keys:

    openssl genpkey -algorithm RSA -out private-key.pem
    openssl rsa -pubout -in private-key.pem -out public-key.pem
""")
    message_renderer = 'markdown'


@adapter_config(name='jwt-proxy-configuration',
                required=(ISecurityManager, IAdminLayer, JWTSecurityConfigurationEditForm),
                provides=IGroup)
class JWTProxyConfigurationGroup(FormGroupChecker):
    """JWT proxy configuration edit group"""

    fields = Fields(IJWTSecurityConfiguration).select(
        'proxy_mode', 'authority', 'get_token_service', 'proxy_access_token_name',
        'proxy_refresh_token_name', 'get_claims_service', 'refresh_token_service',
        'verify_token_service', 'verify_ssl')
    fields['verify_ssl'].widget_factory = SingleCheckBoxFieldWidget

    weight = 20

    def get_content(self):
        return IJWTSecurityConfiguration(self.context)


@viewlet_config(name='jwt-proxy-configuration.header',
                context=ISecurityManager, layer=IAdminLayer, view=JWTProxyConfigurationGroup,
                manager=IHeaderViewletManager, weight=1)
class JWTProxyConfigurationHeader(AlertMessage):
    """JWT proxy configuration header"""

    status = 'info'

    _message = _("JWT authentication module \"proxy mode\" relies on another authentication "
                 "authority (which can be another application using this JWT package) to "
                 "generate, check and refresh tokens. This authority can be used to share "
                 "access tokens between different applications.\n"
                 "You can cache tokens to reduce the number of requests which will be forwarded "
                 "to the authentication authority.")


@adapter_config(name='jwt-proxy-cache-configuration',
                required=(ISecurityManager, IAdminLayer, JWTProxyConfigurationGroup),
                provides=IGroup)
class JWTProxyCacheConfigurationGroup(FormGroupChecker):
    """JWT proxy cache configuration edit group"""

    fields = Fields(IJWTSecurityConfiguration).select('use_cache', 'selected_cache')
