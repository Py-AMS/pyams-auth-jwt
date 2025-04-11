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

"""PyAMS_auth_jwt.zmi module

"""
from datetime import datetime, timedelta, timezone

from pyramid.events import subscriber
from zope.interface import Interface, Invalid

from pyams_auth_jwt.interfaces import IJWTClientKey, IJWTClientKeyContainer
from pyams_auth_jwt.zmi.interfaces import IJWTClientKeyContainerTable
from pyams_form.ajax import ajax_form_config
from pyams_form.field import Fields
from pyams_form.interfaces import DISPLAY_MODE
from pyams_form.interfaces.form import IAJAXFormRenderer, IDataExtractedEvent, IGroup
from pyams_layer.interfaces import IPyAMSLayer
from pyams_security.interfaces import ISecurityManager, IViewContextPermissionChecker
from pyams_security.interfaces.base import MANAGE_SECURITY_PERMISSION
from pyams_skin.interfaces.view import IModalAddForm, IModalEditForm
from pyams_skin.viewlet.actions import ContextAddAction
from pyams_utils.adapter import ContextAdapter, ContextRequestViewAdapter, adapter_config
from pyams_utils.registry import get_utility
from pyams_utils.timezone import tztime
from pyams_utils.url import absolute_url
from pyams_viewlet.viewlet import viewlet_config
from pyams_zmi.form import AdminModalAddForm, AdminModalEditForm, FormGroupChecker
from pyams_zmi.helper.event import get_json_table_row_add_callback, get_json_table_row_refresh_callback
from pyams_zmi.interfaces import IAdminLayer, TITLE_SPAN_BREAK
from pyams_zmi.interfaces.form import IFormTitle
from pyams_zmi.interfaces.table import ITableElementEditor
from pyams_zmi.interfaces.viewlet import IToolbarViewletManager
from pyams_zmi.table import TableElementEditor
from pyams_zmi.utils import get_object_label

__docformat__ = 'restructuredtext'

from pyams_auth_jwt import _


@viewlet_config(name='add-jwt-client-key.action',
                context=ISecurityManager, layer=IAdminLayer, view=IJWTClientKeyContainerTable,
                manager=IToolbarViewletManager, weight=10,
                permission=MANAGE_SECURITY_PERMISSION)
class JWTClientKeyAddAction(ContextAddAction):
    """JWT client key add action"""

    label = _("Add JWT client key")
    href = 'add-jwt-client-key.html'

    def get_href(self):
        container = IJWTClientKeyContainer(self.context)
        return absolute_url(container, self.request, self.href)


@ajax_form_config(name='add-jwt-client-key.html',
                  context=IJWTClientKeyContainer, layer=IPyAMSLayer,
                  permission=MANAGE_SECURITY_PERMISSION)
class JWTClientKeyAddForm(AdminModalAddForm):
    """JWT client key add form"""

    subtitle = _("New JWT client key")
    legend = _("New JWT client key properties")
    modal_class = 'modal-xl'

    fields = Fields(IJWTClientKey).omit('enabled', 'restrict_referrers', 'allowed_referrers')
    content_factory = IJWTClientKey

    def update_widgets(self, prefix=None):
        super().update_widgets(prefix)
        widget = self.widgets.get('public_key')
        if widget is not None:
            widget.rows = 5
            widget.add_class('monospace')
        expiration_date = self.widgets.get('expiration_date')
        if expiration_date is not None:
            now = tztime(datetime.now(timezone.utc))
            expiration_date.value = now + timedelta(days=365)

    def add(self, obj):
        """Add JWT client key to container"""
        self.context[obj.key_id] = obj


@adapter_config(required=(IJWTClientKeyContainer, IAdminLayer, IModalAddForm),
                provides=IFormTitle)
def jwt_client_key_add_form_title(context, request, form):
    """JWT client key add form title getter"""
    translate = request.localizer.translate
    manager = get_utility(ISecurityManager)
    return TITLE_SPAN_BREAK.format(
        get_object_label(manager, request, form),
        translate(_("Plug-in: JWT client keys authentication")))


@adapter_config(name='referrers.group',
                required=(IJWTClientKeyContainer, IAdminLayer, JWTClientKeyAddForm),
                provides=IGroup)
class JWTClientKeyAddFormReferrersGroup(FormGroupChecker):
    """JWT client key add form referrers group"""

    fields = Fields(IJWTClientKey).select('restrict_referrers', 'allowed_referrers')


@subscriber(IDataExtractedEvent, form_selector=JWTClientKeyAddForm)
def handle_jwt_client_key_add_form_data(event):
    """Handle new JWT client key data"""
    data = event.data
    key_id = data.get('key_id')
    if key_id and (key_id in event.form.context):
        event.form.widgets.errors += (Invalid(_("This client ID is already used!")),)


@adapter_config(required=(IJWTClientKeyContainer, IAdminLayer, JWTClientKeyAddForm),
                provides=IAJAXFormRenderer)
class JWTClientKeyAddFormRenderer(ContextRequestViewAdapter):
    """JWT client key add form renderer"""

    def render(self, changes):
        """JSON form renderer"""
        if not changes:
            return None
        sm = get_utility(ISecurityManager)
        return {
            'callbacks': [
                get_json_table_row_add_callback(sm, self.request,
                                                IJWTClientKeyContainerTable, changes)
            ]
        }


@adapter_config(required=(IJWTClientKey, IAdminLayer, Interface),
                provides=ITableElementEditor)
class JWTClientKeyElementEditor(TableElementEditor):
    """JWT client key table element editor"""


@adapter_config(required=IJWTClientKey,
                provides=IViewContextPermissionChecker)
class JWTClientKeyPermissionChecker(ContextAdapter):
    """JWT client key permission checker"""

    edit_permission = MANAGE_SECURITY_PERMISSION


@ajax_form_config(name='properties.html',
                  context=IJWTClientKey, layer=IPyAMSLayer,
                  permission=MANAGE_SECURITY_PERMISSION)
class JWTClientKeyPropertiesEditForm(AdminModalEditForm):
    """JWT client key properties edit form"""

    @property
    def subtitle(self):
        translate = self.request.localizer.translate
        return translate(_("JWT client key: {}")).format(self.context.label)

    legend = _("JWT client key properties")
    modal_class = 'modal-xl'

    fields = Fields(IJWTClientKey).omit('enabled', 'restrict_referrers', 'allowed_referrers')

    def update_widgets(self, prefix=None):
        """Widgets update"""
        super().update_widgets(prefix)
        key_id = self.widgets.get('key_id')
        if key_id is not None:
            key_id.mode = DISPLAY_MODE
        widget = self.widgets.get('public_key')
        if widget is not None:
            widget.rows = 5
            widget.add_class('monospace')


@adapter_config(required=(IJWTClientKey, IAdminLayer, IModalEditForm),
                provides=IFormTitle)
def jwt_client_key_edit_form_title(context, request, form):
    """JWT client key add form title getter"""
    translate = request.localizer.translate
    manager = get_utility(ISecurityManager)
    return TITLE_SPAN_BREAK.format(
        get_object_label(manager, request, form),
        translate(_("Plug-in: JWT client keys authentication")))


@adapter_config(name='referrers.group',
                required=(IJWTClientKey, IAdminLayer, JWTClientKeyPropertiesEditForm),
                provides=IGroup)
class JWTClientKeyPropertiesEditFormReferrersGroup(FormGroupChecker):
    """JWT client key properties edit form referrers group"""

    fields = Fields(IJWTClientKey).select('restrict_referrers', 'allowed_referrers')


@adapter_config(required=(IJWTClientKey, IAdminLayer, JWTClientKeyPropertiesEditForm),
                provides=IAJAXFormRenderer)
class JWTClientKeyPropertiesEditFormRenderer(ContextRequestViewAdapter):
    """JWT client key properties edit form renderer"""

    def render(self, changes):
        """JSON form renderer"""
        if not changes:
            return None
        sm = get_utility(ISecurityManager)
        return {
            'status': 'success',
            'message': self.request.localizer.translate(self.view.success_message),
            'callbacks': [
                get_json_table_row_refresh_callback(sm, self.request,
                                                    IJWTClientKeyContainerTable, self.context)
            ]
        }
