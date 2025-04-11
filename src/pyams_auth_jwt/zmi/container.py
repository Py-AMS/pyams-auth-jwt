# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#

from pyramid.decorator import reify
from pyramid.view import view_config

from pyams_auth_jwt.interfaces import IJWTClientKeyContainer
from pyams_auth_jwt.zmi.interfaces import IJWTClientKeyContainerTable, IJWTSecurityConfigurationMenu
from pyams_layer.interfaces import IPyAMSLayer
from pyams_pagelet.pagelet import pagelet_config
from pyams_security.interfaces import ISecurityManager
from pyams_security.interfaces.base import MANAGE_SECURITY_PERMISSION
from pyams_table.column import GetAttrColumn
from pyams_table.interfaces import IColumn, IValues
from pyams_utils.adapter import ContextRequestViewAdapter, adapter_config
from pyams_utils.date import format_datetime
from pyams_utils.factory import factory_config
from pyams_utils.interfaces import MISSING_INFO
from pyams_utils.url import absolute_url
from pyams_viewlet.viewlet import viewlet_config
from pyams_zmi.helper.container import delete_container_element, switch_element_attribute
from pyams_zmi.interfaces import IAdminLayer
from pyams_zmi.table import AttributeSwitcherColumn, I18nColumnMixin, Table, TableAdminView, TrashColumn
from pyams_zmi.zmi.viewlet.menu import NavigationMenuItem

__docformat__ = 'restructuredtext'

from pyams_auth_jwt import _


@viewlet_config(name='jwt-client-key-container.menu',
                context=ISecurityManager, layer=IAdminLayer,
                manager=IJWTSecurityConfigurationMenu, weight=10,
                permission=MANAGE_SECURITY_PERMISSION)
class JWTClientKeyContainerMenu(NavigationMenuItem):
    """JWT client key container menu"""
    
    label = _("JWT client keys")
    href = '#jwt-client-key-container.html'
    
    
@factory_config(IJWTClientKeyContainerTable)
class JWTClientKeyContainerTable(Table):
    """JWT client key container table"""
    
    display_if_empty = True
    
    @reify
    def data_attributes(self):
        attributes = super().data_attributes
        container = IJWTClientKeyContainer(self.context)
        attributes['table'].update({
            'data-ams-order': '1,asc',
            'data-ams-location': absolute_url(container, self.request)
        })
        return attributes


@adapter_config(required=(ISecurityManager, IAdminLayer, IJWTClientKeyContainerTable),
                provides=IValues)
class JWTClientKeyContainerTableValues(ContextRequestViewAdapter):
    """JWT client keys container table values adapter"""

    @property
    def values(self):
        """Table values getter"""
        yield from IJWTClientKeyContainer(self.context).values()


@adapter_config(name='enabled',
                required=(ISecurityManager, IAdminLayer, IJWTClientKeyContainerTable),
                provides=IColumn)
class JWTClientKeyEnabledSwitcherColumn(AttributeSwitcherColumn):
    """JWT client key enabled column"""

    hint = _("Click icon to enable or disable this client key")

    attribute_name = 'enabled'
    attribute_switcher = 'switch-enabled-key.json'

    icon_on_class = 'fas fa-shop-lock'
    icon_off_class = 'fas fa-shop-slash text-danger'

    weight = 10


@view_config(name='switch-enabled-key.json',
             context=IJWTClientKeyContainer, request_type=IPyAMSLayer,
             renderer='json', xhr=True)
def switch_enabled_key(request):
    """Switch enabled JWT client key"""
    return switch_element_attribute(request)


@adapter_config(name='name',
                required=(IJWTClientKeyContainer, IAdminLayer, IJWTClientKeyContainerTable),
                provides=IColumn)
class JWTClientKeyNameColumn(I18nColumnMixin, GetAttrColumn):
    """JWT client key container name column"""

    i18n_header = _("Key ID")
    attr_name = 'key_id'

    weight = 20


@adapter_config(name='label',
                required=(ISecurityManager, IAdminLayer, IJWTClientKeyContainerTable),
                provides=IColumn)
class JWTClientKeyLabelColumn(I18nColumnMixin, GetAttrColumn):
    """JWT client key container label column"""

    i18n_header = _("Label")
    attr_name = 'label'

    weight = 30

    def get_value(self, obj):
        """Value getter"""
        return super().get_value(obj) or MISSING_INFO


@adapter_config(name='issuer',
                required=(ISecurityManager, IAdminLayer, IJWTClientKeyContainerTable),
                provides=IColumn)
class JWTClientKeyIssuerColumn(I18nColumnMixin, GetAttrColumn):
    """JWT client key container issuer column"""

    i18n_header = _("Issuer")
    attr_name = 'issuer'

    weight = 32

    def get_value(self, obj):
        """Value getter"""
        return super().get_value(obj) or MISSING_INFO


@adapter_config(name='audience',
                required=(ISecurityManager, IAdminLayer, IJWTClientKeyContainerTable),
                provides=IColumn)
class JWTClientKeyAudienceColumn(I18nColumnMixin, GetAttrColumn):
    """JWT client key container audience column"""

    i18n_header = _("Audience")
    attr_name = 'audience'

    weight = 34

    def get_value(self, obj):
        """Value getter"""
        return super().get_value(obj) or MISSING_INFO


@adapter_config(name='principal',
                required=(ISecurityManager, IAdminLayer, IJWTClientKeyContainerTable),
                provides=IColumn)
class JWTClientKeyPrincipalColumn(I18nColumnMixin, GetAttrColumn):
    """JWT client key container principal column"""

    i18n_header = _("Principal")

    weight = 40

    def get_value(self, obj):
        """Value getter"""
        if not obj.principal_id:
            return MISSING_INFO
        principal = obj.get_principal(self.request)
        return principal.title if principal is not None else MISSING_INFO


@adapter_config(name='activation_date',
                required=(ISecurityManager, IAdminLayer, IJWTClientKeyContainerTable),
                provides=IColumn)
class JWTClientKeyActivationDateColumn(I18nColumnMixin, GetAttrColumn):
    """JWT client key container activation date column"""

    i18n_header = _("Activation date")
    attr_name = 'activation_date'

    weight = 50

    def get_value(self, obj):
        """Activation date getter"""
        activation_date = super().get_value(obj)
        return format_datetime(activation_date)


@adapter_config(name='expiration_date',
                required=(ISecurityManager, IAdminLayer, IJWTClientKeyContainerTable),
                provides=IColumn)
class JWTClientKeyExpirationDateColumn(I18nColumnMixin, GetAttrColumn):
    """JWT client key container expiration date column"""

    i18n_header = _("Expiration date")
    attr_name = 'expiration_date'

    weight = 60

    def get_value(self, obj):
        """Expiration date getter"""
        expiration_date = super().get_value(obj)
        return format_datetime(expiration_date)


@adapter_config(name='trash',
                required=(ISecurityManager, IAdminLayer, IJWTClientKeyContainerTable),
                provides=IColumn)
class JWTClientKeyTrashColumn(TrashColumn):
    """JWT client key container trash column"""


@view_config(name='delete-element.json',
             context=IJWTClientKeyContainer, request_type=IPyAMSLayer,
             permission=MANAGE_SECURITY_PERMISSION, renderer='json', xhr=True)
def delete_apikey(request):
    """JWT client key delete view"""
    return delete_container_element(request)


@pagelet_config(name='jwt-client-key-container.html',
                context=ISecurityManager, layer=IPyAMSLayer,
                permission=MANAGE_SECURITY_PERMISSION, xhr=True)
class JWTClientKeyContainerView(TableAdminView):
    """JWT client key container view"""

    table_label = _("JWT client keys")
    table_class = IJWTClientKeyContainerTable
