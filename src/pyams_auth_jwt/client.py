# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#

from datetime import datetime, timezone

from BTrees.OOBTree import OOBTree
from persistent import Persistent
from zope.container.contained import Contained
from zope.container.folder import Folder
from zope.location.interfaces import ISublocations
from zope.schema.fieldproperty import FieldProperty
from zope.traversing.interfaces import ITraversable

from pyams_auth_jwt.interfaces import IJWTAuthenticationPlugin, IJWTClientKey, IJWTClientKeyContainer, \
    IJWTSecurityConfiguration, JWT_CLIENT_CONTAINER_KEY, JWT_PREFIX
from pyams_security.interfaces import ISecurityManager
from pyams_security.interfaces.names import PRINCIPAL_ID_FORMATTER
from pyams_security.principal import PrincipalInfo
from pyams_security.utility import get_principal
from pyams_utils.adapter import ContextAdapter, adapter_config, get_annotation_adapter
from pyams_utils.factory import factory_config
from pyams_utils.request import query_request
from pyams_utils.timezone import tztime
from pyams_utils.zodb import volatile_property

__docformat__ = 'restructuredtext'

from pyams_auth_jwt import _


@factory_config(IJWTClientKey)
class JWTClientKey(Persistent, Contained):
    """JWT client key"""

    key_id = FieldProperty(IJWTClientKey['key_id'])
    _enabled = FieldProperty(IJWTClientKey['enabled'])
    label = FieldProperty(IJWTClientKey['label'])
    issuer = FieldProperty(IJWTClientKey['issuer'])
    audience = FieldProperty(IJWTClientKey['audience'])
    public_key = FieldProperty(IJWTClientKey['public_key'])
    algorithm = FieldProperty(IJWTClientKey['algorithm'])
    _principal_id = FieldProperty(IJWTClientKey['principal_id'])
    _activation_date = FieldProperty(IJWTClientKey['activation_date'])
    _expiration_date = FieldProperty(IJWTClientKey['expiration_date'])
    restrict_referrers = FieldProperty(IJWTClientKey['restrict_referrers'])
    allowed_referrers = FieldProperty(IJWTClientKey['allowed_referrers'])

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)

    @property
    def enabled(self):
        """Enabled field getter"""
        return self._enabled

    @enabled.setter
    def enabled(self, value):
        """Enabled field setter"""
        if value != self._enabled:
            self._enabled = value
            del self.active

    @property
    def principal_id(self):
        """Principal ID getter"""
        return self._principal_id

    @principal_id.setter
    def principal_id(self, value):
        """Principal ID setter"""
        container = self.__parent__
        if container is not None:
            container.update_key(self, self._principal_id, value)
        self._principal_id = value

    @property
    def activation_date(self):
        """Activation date field getter"""
        return self._activation_date

    @activation_date.setter
    def activation_date(self, value):
        """Activation date field setter"""
        if value != self._activation_date:
            self._activation_date = value
            del self.active

    @property
    def expiration_date(self):
        """Expiration date field getter"""
        return self._expiration_date

    @expiration_date.setter
    def expiration_date(self, value):
        """Expiration date field setter"""
        if value != self._expiration_date:
            self._expiration_date = value
            del self.active

    @volatile_property
    def active(self):
        """Key activity checker"""
        if not self.enabled:
            return False
        now = tztime(datetime.now(timezone.utc))
        if self.activation_date and (self.activation_date > now):
            return False
        if self.expiration_date and (self.expiration_date < now):
            return False
        return True

    def get_principal(self, request=None, allow_redirect=True):
        """Get principal matching this client key"""
        if not self.active:
            return None
        if request is None:
            request = query_request()
        if self.restrict_referrers:
            origin = request.headers.get('Origin', request.host_url)
            if not ((origin == request.host_url) or (origin in self.allowed_referrers or ())):
                return None
        if self.principal_id and allow_redirect:
            return get_principal(request, self.principal_id)
        translate = request.localizer.translate
        return PrincipalInfo(id=PRINCIPAL_ID_FORMATTER.format(prefix=JWT_PREFIX, login=self.key_id),
                             title=translate(_("JWT client key: {}")).format(self.label))

    
@factory_config(IJWTClientKeyContainer)
class JWTClientKeyContainer(Folder):
    """JWT client key container"""
    
    by_key = None
    by_principal = None
    
    def _newContainerData(self):
        """Create new container data"""
        data = super()._newContainerData()
        self.by_key = OOBTree()
        self.by_principal = OOBTree()
        return data

    def __setitem__(self, key, value):
        """Store new API key"""
        super().__setitem__(key, value)
        self.by_key[value.key_id] = value
        if value.principal_id:
            self.by_principal.setdefault(value.principal_id, []).append(value)

    def __delitem__(self, key):
        """Del API key"""
        client_key = self.get(key)
        if client_key is not None:
            del self.by_key[client_key.key_id]
            if client_key.principal_id:
                keys = self.by_principal.get(client_key.principal_id)
                if client_key in keys:
                    keys.remove(client_key)
                if keys:
                    self.by_principal[client_key.principal_id] = keys
                else:
                    del self.by_principal[client_key.principal_id]
        super().__delitem__(key)

    def update_key(self, client_key, old_principal_id, new_principal_id):
        """Update client key"""
        keys = self.by_principal.get(old_principal_id)
        if keys:
            if client_key in keys:
                keys.remove(client_key)
            if keys:
                self.by_principal[old_principal_id] = keys
            else:
                del self.by_principal[old_principal_id]
        if new_principal_id:
            self.by_principal.setdefault(new_principal_id, []).append(client_key)


@adapter_config(required=IJWTSecurityConfiguration,
                provides=IJWTClientKeyContainer)
def jwt_client_key_container(context):
    """JWT client key container adapter"""
    return get_annotation_adapter(context, JWT_CLIENT_CONTAINER_KEY, IJWTClientKeyContainer,
                                  name='++clients++')


@adapter_config(name='clients',
                required=IJWTSecurityConfiguration,
                provides=ITraversable)
class JWTSecurityConfigurationClientsTraverser(ContextAdapter):
    """JWT security configuration clients traverser"""
    
    def traverse(self, name, furtherPath=None):
        return IJWTClientKeyContainer(self.context, None)
    
    
@adapter_config(name='clients',
                required=IJWTSecurityConfiguration,
                provides=ISublocations)
class JWTSecurityConfigurationClientsSublocations(ContextAdapter):
    """JWT security configuration clients sublocations"""
    
    def sublocations(self):
        container = IJWTClientKeyContainer(self.context, None)
        if container is not None:
            yield from container.values()
    

@adapter_config(required=ISecurityManager,
                provides=IJWTClientKeyContainer)
def security_manager_client_key_container(context):
    """Security manager client key configuration adapter"""
    configuration = IJWTSecurityConfiguration(context, None)
    return IJWTClientKeyContainer(configuration, None)
