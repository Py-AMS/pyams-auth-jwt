================================
PyAMS JWT authentication package
================================


Introduction
------------

This package is composed of a set of utility functions, usable into any Pyramid application.
It's an extension to PyAMS_security, which provides features to generate JWT tokens, and extract
credentials from matching "Authorization headers:

    >>> import pprint

    >>> from pyramid.testing import setUp, tearDown, DummyRequest
    >>> from pyramid.threadlocal import manager
    >>> config = setUp(hook_zca=True)
    >>> config.registry.settings['zodbconn.uri'] = 'memory://'

    >>> from beaker.cache import CacheManager, cache_regions
    >>> cache = CacheManager(**{'cache.type': 'memory'})
    >>> cache_regions.update({'short': {'type': 'memory', 'expire': 10}})
    >>> cache_regions.update({'default': {'type': 'memory', 'expire': 60}})
    >>> cache_regions.update({'long': {'type': 'memory', 'expire': 600}})

    >>> from pyramid_zodbconn import includeme as include_zodbconn
    >>> include_zodbconn(config)
    >>> from cornice import includeme as include_cornice
    >>> include_cornice(config)
    >>> from pyams_utils import includeme as include_utils
    >>> include_utils(config)
    >>> from pyams_site import includeme as include_site
    >>> include_site(config)
    >>> from pyams_security import includeme as include_security
    >>> include_security(config)
    >>> from pyams_auth_jwt import includeme as include_auth_jwt
    >>> include_auth_jwt(config)

    >>> from pyams_utils.registry import get_utility, set_local_registry
    >>> registry = config.registry
    >>> set_local_registry(registry)

    >>> from pyams_site.generations import upgrade_site
    >>> request = DummyRequest()
    >>> app = upgrade_site(request)
    Upgrading PyAMS timezone to generation 1...
    Upgrading PyAMS security to generation 2...

    >>> from zope.traversing.interfaces import BeforeTraverseEvent
    >>> from pyams_utils.registry import handle_site_before_traverse
    >>> handle_site_before_traverse(BeforeTraverseEvent(app, request))

    >>> from pyams_security.interfaces import ISecurityManager
    >>> sm = get_utility(ISecurityManager)

    >>> from pyams_security.interfaces import ICredentialsPlugin
    >>> plugin = get_utility(ICredentialsPlugin, name='jwt')


Using PyAMS security policy
---------------------------

The plugin should be included correctly into PyAMS security policy:

    >>> from pyramid.authorization import ACLAuthorizationPolicy
    >>> config.set_authorization_policy(ACLAuthorizationPolicy())

    >>> from pyams_security.policy import PyAMSAuthenticationPolicy
    >>> policy = PyAMSAuthenticationPolicy(secret='my secret',
    ...                                    http_only=True,
    ...                                    secure=False)
    >>> config.set_authentication_policy(policy)

    >>> from pyams_security.tests import new_test_request
    >>> request = new_test_request('admin', 'admin', registry=config.registry)

    >>> plugin in sm.credentials_plugins
    True
    >>> plugin in sm.authentication_plugins
    False
    >>> plugin in sm.directory_plugins
    False


Using JWT authentication
------------------------

You can login on PyAMS application server using a JWT token, is this one is activated.
Please note that using JWT is not mandatory, you can combine JWT with other authentication
methods.

You have to set several security manager properties to use JWT:

    >>> from pyams_utils.factory import register_factory
    >>> from pyams_auth_jwt.interfaces import IJWTSecurityConfiguration
    >>> from pyams_auth_jwt.plugin import JWTSecurityConfiguration
    >>> register_factory(IJWTSecurityConfiguration, JWTSecurityConfiguration)

    >>> jwt_configuration = IJWTSecurityConfiguration(sm)
    >>> jwt_configuration.secret = ''
    >>> jwt_configuration.local_mode = True

    >>> plugin.enabled
    True

    >>> errors = []
    >>> IJWTSecurityConfiguration.validateInvariants(jwt_configuration, errors)
    Traceback (most recent call last):
    ...
    zope.interface.exceptions.Invalid: [Invalid('You must define a private and a public key to use RS256 algorithm'...)]

    >>> jwt_configuration.algorithm = 'HS256'
    >>> jwt_configuration.secret = 'my secret'

    >>> errors = []
    >>> IJWTSecurityConfiguration.validateInvariants(jwt_configuration, errors)
    >>> errors
    []

    >>> from pyams_auth_jwt.plugin import create_jwt_token, get_jwt_claims
    >>> from pyams_auth_jwt.api import get_jwt_token

    >>> DummyRequest().unauthenticated_userid is None
    True

    >>> jwt_request = DummyRequest(method='POST', path='/api/auth/jwt/login',
    ...                            params={'login': 'user1', 'password': 'passwd'})
    >>> jwt_request.create_jwt_token = lambda *args, **kwargs: create_jwt_token(jwt_request, *args, **kwargs)
    >>> jwt_result = get_jwt_token(jwt_request)
    >>> pprint.pprint(jwt_result)
    {'message': 'Invalid credentials!', 'status': 'error'}

This error is normal, because the user doesn't actually exist! So let's create it:

    >>> from pyams_security.plugin.userfolder import UsersFolder
    >>> folder = UsersFolder()
    >>> folder.prefix = 'users'
    >>> folder.title = 'Local users folder'
    >>> sm['users'] = folder

    >>> from pyams_security.plugin.userfolder import LocalUser
    >>> user1 = LocalUser()
    >>> user1.self_registered = False
    >>> user1.login = 'user1'
    >>> user1.email = 'user@example.com'
    >>> user1.firstname = 'John'
    >>> user1.lastname = 'Doe'
    >>> user1.password = 'passwd'
    >>> user1.activated = True
    >>> folder[user1.login] = user1

    >>> jwt_result = get_jwt_token(jwt_request)
    >>> pprint.pprint(jwt_result)
    {'accessToken': 'eyJ...',
     'refreshToken': 'eyJ...',
     'status': 'success'}

Let's now try to use this token; this requires a Beaker cache:

    >>> jwt_request = DummyRequest(authorization=('Bearer', jwt_result['accessToken']))
    >>> jwt_request.unauthenticated_userid
    'users:user1'
    >>> jwt_principal_id = sm.authenticated_userid(jwt_request)
    >>> jwt_principal_id
    'users:user1'

    >>> plugin.unauthenticated_userid(jwt_request)
    'users:user1'


JWT authentication generally don't use cookies; but "remember" and "forget" authentication
policy methods can be used anyway, and will return usual cookies:

    >>> policy.authenticated_userid(jwt_request)
    'users:user1'
    >>> policy.remember(jwt_request, jwt_principal_id)
    [('Set-Cookie', 'auth_ticket=...!userid_type:b64unicode; Path=/; HttpOnly; SameSite=Lax'),...]
    >>> policy.forget(jwt_request)
    [('Set-Cookie', 'auth_ticket=; Max-Age=0; Path=/; expires=Wed, 31-Dec-97 23:59:59 GMT; HttpOnly; SameSite=Lax'),
     ('Set-Cookie', 'auth_ticket=; Domain=example.com; Max-Age=0; Path=/; expires=Wed, 31-Dec-97 23:59:59 GMT; HttpOnly; SameSite=Lax'),
     ('Set-Cookie', 'auth_ticket=; Domain=.example.com; Max-Age=0; Path=/; expires=Wed, 31-Dec-97 23:59:59 GMT; HttpOnly; SameSite=Lax')]

We can try the same process using bad credentials or a bad JWT token:

    >>> jwt_request = DummyRequest(method='POST', path='/api/auth/jwt/login',
    ...                            params={'login': 'user1', 'password': 'badpasswd'})
    >>> jwt_request.create_jwt_token = lambda *args, **kwargs: create_jwt_token(jwt_request, *args, **kwargs)
    >>> jwt_result = get_jwt_token(jwt_request)
    >>> pprint.pprint(jwt_result)
    {'message': 'Invalid credentials!', 'status': 'error'}

    >>> jwt_request = DummyRequest(authorization=('Bearer', 'abc.def.ghi'), remote_addr='127.0.0.1')
    >>> jwt_principal_id = sm.authenticated_userid(jwt_request)
    >>> jwt_principal_id is None
    True
    >>> policy.authenticated_userid(jwt_request) is None
    True


Let's try to use another JWT configuration:

    >>> jwt_configuration.algorithm = 'RS512'
    >>> jwt_configuration.public_key = """-----BEGIN PUBLIC KEY-----
    ... MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv
    ... vkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc
    ... aT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy
    ... tvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0
    ... e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb
    ... V6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9
    ... MwIDAQAB
    ... -----END PUBLIC KEY-----"""
    >>> jwt_configuration.private_key = '''-----BEGIN RSA PRIVATE KEY-----
    ... MIIEogIBAAKCAQEAnzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA+kzeVOVpVWw
    ... kWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr/Mr
    ... m/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEi
    ... NQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e+lf4s4OxQawWD79J9/5d3Ry0vbV
    ... 3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa+GSYOD2
    ... QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9MwIDAQABAoIBACiARq2wkltjtcjs
    ... kFvZ7w1JAORHbEufEO1Eu27zOIlqbgyAcAl7q+/1bip4Z/x1IVES84/yTaM8p0go
    ... amMhvgry/mS8vNi1BN2SAZEnb/7xSxbflb70bX9RHLJqKnp5GZe2jexw+wyXlwaM
    ... +bclUCrh9e1ltH7IvUrRrQnFJfh+is1fRon9Co9Li0GwoN0x0byrrngU8Ak3Y6D9
    ... D8GjQA4Elm94ST3izJv8iCOLSDBmzsPsXfcCUZfmTfZ5DbUDMbMxRnSo3nQeoKGC
    ... 0Lj9FkWcfmLcpGlSXTO+Ww1L7EGq+PT3NtRae1FZPwjddQ1/4V905kyQFLamAA5Y
    ... lSpE2wkCgYEAy1OPLQcZt4NQnQzPz2SBJqQN2P5u3vXl+zNVKP8w4eBv0vWuJJF+
    ... hkGNnSxXQrTkvDOIUddSKOzHHgSg4nY6K02ecyT0PPm/UZvtRpWrnBjcEVtHEJNp
    ... bU9pLD5iZ0J9sbzPU/LxPmuAP2Bs8JmTn6aFRspFrP7W0s1Nmk2jsm0CgYEAyH0X
    ... +jpoqxj4efZfkUrg5GbSEhf+dZglf0tTOA5bVg8IYwtmNk/pniLG/zI7c+GlTc9B
    ... BwfMr59EzBq/eFMI7+LgXaVUsM/sS4Ry+yeK6SJx/otIMWtDfqxsLD8CPMCRvecC
    ... 2Pip4uSgrl0MOebl9XKp57GoaUWRWRHqwV4Y6h8CgYAZhI4mh4qZtnhKjY4TKDjx
    ... QYufXSdLAi9v3FxmvchDwOgn4L+PRVdMwDNms2bsL0m5uPn104EzM6w1vzz1zwKz
    ... 5pTpPI0OjgWN13Tq8+PKvm/4Ga2MjgOgPWQkslulO/oMcXbPwWC3hcRdr9tcQtn9
    ... Imf9n2spL/6EDFId+Hp/7QKBgAqlWdiXsWckdE1Fn91/NGHsc8syKvjjk1onDcw0
    ... NvVi5vcba9oGdElJX3e9mxqUKMrw7msJJv1MX8LWyMQC5L6YNYHDfbPF1q5L4i8j
    ... 8mRex97UVokJQRRA452V2vCO6S5ETgpnad36de3MUxHgCOX3qL382Qx9/THVmbma
    ... 3YfRAoGAUxL/Eu5yvMK8SAt/dJK6FedngcM3JEFNplmtLYVLWhkIlNRGDwkg3I5K
    ... y18Ae9n7dHVueyslrb6weq7dTkYDi3iOYRW8HRkIQh06wEdbxt0shTzAJvvCQfrB
    ... jg/3747WSsf/zBTcHihTRBdAv6OmdhV4/dD5YBfLAkLrd+mX7iE=
    ... -----END RSA PRIVATE KEY-----'''
    >>> jwt_configuration.access_expiration = 3600

    >>> errors = []
    >>> IJWTSecurityConfiguration.validateInvariants(jwt_configuration, errors)
    >>> errors
    []

    >>> from zope.lifecycleevent import ObjectModifiedEvent
    >>> config.registry.notify(ObjectModifiedEvent(jwt_configuration))

    >>> from pyams_utils.registry import get_utility
    >>> from pyams_auth_jwt.interfaces import IJWTAuthenticationPlugin
    >>> plugin = get_utility(IJWTAuthenticationPlugin)
    >>> plugin.audience = 'app:app1'

    >>> jwt_request = DummyRequest(method='POST', path='/api/auth/jwt/login',
    ...                            params={'login': 'user1', 'password': 'passwd'})
    >>> jwt_request.create_jwt_token = lambda *args, **kwargs: create_jwt_token(jwt_request, *args, **kwargs)
    >>> jwt_result = get_jwt_token(jwt_request)
    >>> pprint.pprint(jwt_result)
    {'accessToken': 'eyJ...',
     'refreshToken': 'eyJ...',
     'status': 'success'}

    >>> jwt_request = DummyRequest(authorization=('Bearer', jwt_result['accessToken']))
    >>> jwt_request.get_jwt_claims = lambda *args, **kwargs: get_jwt_claims(jwt_request, *args, **kwargs)
    >>> pprint.pprint(jwt_request.get_jwt_claims())
    {'aud': 'app:app1',
     'exp': ...,
     'iat': ...,
     'obj': 'access',
     'sub': 'users:user1'}

We are also going to change the token authorization type:

    >>> config.registry.settings['pyams.jwt.auth_type'] = 'JWT'

    >>> jwt_request = DummyRequest()
    >>> jwt_request.get_jwt_claims = lambda *args, **kwargs: get_jwt_claims(jwt_request, *args, **kwargs)
    >>> pprint.pprint(jwt_request.get_jwt_claims())
    {}

    >>> jwt_request = DummyRequest(authorization=('Bearer', jwt_result['accessToken']))
    >>> jwt_request.get_jwt_claims = lambda *args, **kwargs: get_jwt_claims(jwt_request, *args, **kwargs)
    >>> pprint.pprint(jwt_request.get_jwt_claims())
    {}

    >>> jwt_request = DummyRequest(authorization=('JWT', jwt_result['accessToken']))
    >>> jwt_request.get_jwt_claims = lambda *args, **kwargs: get_jwt_claims(jwt_request, *args, **kwargs)
    >>> pprint.pprint(jwt_request.get_jwt_claims())
    {'aud': 'app:app1',
     'exp': ...,
     'iat': ...,
     'obj': 'access',
     'sub': 'users:user1'}

    >>> plugin.unauthenticated_userid(jwt_request)
    'users:user1'

We can also change the HTTP header used to get JWT token:

    >>> config.registry.settings['pyams.jwt.http_header'] = 'X-PyAMS-Authorization'

    >>> jwt_request = DummyRequest()
    >>> jwt_request.get_jwt_claims = lambda *args, **kwargs: get_jwt_claims(jwt_request, *args, **kwargs)
    >>> pprint.pprint(jwt_request.get_jwt_claims())
    {}

    >>> jwt_request = DummyRequest(headers={'X-PyAMS-Authorization': jwt_result['accessToken']})
    >>> jwt_request.get_jwt_claims = lambda *args, **kwargs: get_jwt_claims(jwt_request, *args, **kwargs)
    >>> pprint.pprint(jwt_request.get_jwt_claims())
    {'aud': 'app:app1',
     'exp': ...,
     'iat': ...,
     'obj': 'access',
     'sub': 'users:user1'}

    >>> del config.registry.settings['pyams.jwt.http_header']

Disabling the JWT configuration always return empty results:

    >>> jwt_configuration.local_mode = False
    >>> jwt_request.unauthenticated_userid is None
    True

Claims are stored into request environment, so we have to create a new request:

    >>> jwt_request = DummyRequest(authorization=('JWT', jwt_result['accessToken']))
    >>> jwt_request.get_jwt_claims = lambda *args, **kwargs: get_jwt_claims(jwt_request, *args, **kwargs)
    >>> pprint.pprint(jwt_request.get_jwt_claims())
    {}

    >>> jwt_request = DummyRequest(method='POST', path='/api/auth/jwt/token',
    ...                            params={'login': 'user1', 'password': 'passwd'})
    >>> jwt_request.create_jwt_token = lambda *args, **kwargs: create_jwt_token(jwt_request, *args, **kwargs)
    >>> jwt_result = get_jwt_token(jwt_request)
    Traceback (most recent call last):
    ...
    pyramid.httpexceptions.HTTPServiceUnavailable: The server is currently unavailable. Please try again at a later time.


Testing plugin API
------------------

We first have to get JWT tokens; let's reactivate our plug-in:

    >>> config.registry.settings['pyams.jwt.auth_type'] = 'Bearer'
    >>> jwt_configuration.local_mode = True

    >>> jwt_request = DummyRequest(method='PATCH', path='/api/auth/jwt/token')
    >>> jwt_request.create_jwt_token = lambda *args, **kwargs: create_jwt_token(jwt_request, *args, **kwargs)
    >>> jwt_result = get_jwt_token(jwt_request)
    Traceback (most recent call last):
    ...
    pyramid.httpexceptions.HTTPBadRequest: The server could not comply with the request since it is either malformed or otherwise incorrect.

    >>> jwt_request = DummyRequest(method='PATCH', path='/api/auth/jwt/token',
    ...                            params={'login': 'user1', 'password': 'passwd'})
    >>> jwt_result = get_jwt_token(jwt_request)
    >>> pprint.pprint(jwt_result)
    {'accessToken': 'eyJ...',
     'refreshToken': 'eyJ...',
     'status': 'success'}

We can now try to get a new access token, using the previous refresh token:

    >>> from pyams_auth_jwt.api import refresh_jwt_token

    >>> jwt_request = DummyRequest(authorization=('Bearer', jwt_result['refreshToken']))
    >>> jwt_request.get_jwt_claims = lambda *args, **kwargs: get_jwt_claims(jwt_request, *args, **kwargs)
    >>> pprint.pprint(jwt_request.get_jwt_claims())
    {'aud': 'app:app1',
     'exp': ...,
     'iat': ...,
     'obj': 'refresh',
     'sub': 'users:user1'}
    >>> jwt_refresh = refresh_jwt_token(jwt_request)
    >>> pprint.pprint(jwt_refresh)
    {'accessToken': 'eyJ...',
     'status': 'success'}

    >>> import jwt
    >>> pprint.pprint(jwt.decode(jwt_refresh['accessToken'], key=jwt_configuration.public_key,
    ...                          algorithms=[jwt_configuration.algorithm], audience='app:app1'))
    {'aud': 'app:app1',
     'exp': ...,
     'iat': ...,
     'obj': 'access',
     'sub': 'users:user1'}

We can also get claims from a given token:

    >>> from pyams_auth_jwt.api import get_jwt_claims
    >>> pprint.pprint(get_jwt_claims(jwt_request))
    {'aud': 'app:app1',
     'exp': ...,
     'iat': ...,
     'obj': 'refresh',
     'sub': 'users:user1'}

We can always try o refresh a token without providing any access token:

    >>> jwt_request = DummyRequest()
    >>> jwt_request.get_jwt_claims = lambda *args, **kwargs: get_jwt_claims(jwt_request, *args, **kwargs)
    >>> refresh_jwt_token(jwt_request)
    Traceback (most recent call last):
    ...
    pyramid.httpexceptions.HTTPForbidden: Access was denied to this resource.


Let's finally try to verify a token; this requires a POST on another access point:

    >>> from pyams_auth_jwt.api import verify_jwt_token

    >>> jwt_request = DummyRequest(authorization=('Bearer', jwt_result['refreshToken']))
    >>> jwt_request.get_jwt_claims = lambda *args, **kwargs: get_jwt_claims(jwt_request, *args, **kwargs)
    >>> verify_jwt_token(jwt_request)
    {'status': 'success'}

    >>> another_token = 'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJvYmoiOiJhY2Nlc3MiLCJpYXQiOjE2MDg2NDU2NzQsImV4cCI6MTYwODY0OTI3NCwic3ViIjoic3lzdGVtOmFkbWluIn0.HeKZILlFb9qWA0quEwlLTlgWGA3nMx32bsnao1GFNxSR5_7NDlG3XJhzMMWvR7iMwf6u2AdLiVajZSDtpi1UVQ'
    >>> jwt_request = DummyRequest(authorization=('Bearer', another_token))
    >>> jwt_request.get_jwt_claims = lambda *args, **kwargs: get_jwt_claims(jwt_request, *args, **kwargs)
    >>> verify_jwt_token(jwt_request)
    Traceback (most recent call last):
    ...
    pyramid.httpexceptions.HTTPForbidden: ...


Custom JWT tokens object predicate
----------------------------------

When a view is protected by a JWT token, you can add a custom predicate to specify which token
type is authorized.

PyAMS JWT plug-in actually provides two tokens objects, which are "access" and "refresh".

    >>> from pyams_auth_jwt.interfaces import ACCESS_OBJECT
    >>> from pyams_auth_jwt.plugin import JWTTokenObjectPredicate

    >>> predicate = JWTTokenObjectPredicate(ACCESS_OBJECT, config)
    >>> predicate.text()
    'jwt_object = access'

    >>> jwt_request = DummyRequest(method='POST', path='/api/auth/jwt/login',
    ...                            params={'login': 'user1', 'password': 'passwd'})
    >>> jwt_request.create_jwt_token = lambda *args, **kwargs: create_jwt_token(jwt_request, *args, **kwargs)
    >>> jwt_request.get_jwt_claims = lambda *args, **kwargs: get_jwt_claims(jwt_request, *args, **kwargs)
    >>> jwt_result = get_jwt_token(jwt_request)
    >>> pprint.pprint(jwt_result)
    {'accessToken': 'eyJ...',
     'refreshToken': 'eyJ...',
     'status': 'success'}

    >>> jwt_access = DummyRequest(authorization=('Bearer', jwt_result['accessToken']))
    >>> jwt_access.get_jwt_claims = lambda *args, **kwargs: get_jwt_claims(jwt_request, *args, **kwargs)
    >>> predicate(None, jwt_access)
    True

    >>> jwt_refresh = DummyRequest(authorization=('Bearer', jwt_result['refreshToken']))
    >>> jwt_refresh.get_jwt_claims = lambda *args, **kwargs: get_jwt_claims(jwt_request, *args, **kwargs)
    >>> predicate(None, jwt_refresh)
    False


JWT plugin proxy mode
---------------------

Let's try to see how proxy mode is supported:

    >>> jwt_configuration.proxy_mode = True
    >>> IJWTSecurityConfiguration.validateInvariants(jwt_configuration)
    Traceback (most recent call last):
    ...
    zope.interface.exceptions.Invalid: You can't enable both local and proxy modes

You can't use both local and proxy mode!

    >>> jwt_configuration.local_mode = False
    >>> jwt_configuration.proxy_mode = True
    >>> IJWTSecurityConfiguration.validateInvariants(jwt_configuration)
    Traceback (most recent call last):
    ...
    zope.interface.exceptions.Invalid: You must define authentication authority to use proxy mode

Yes, we now have to configure our authentication authentication authority:

    >>> jwt_configuration.authority = 'http://localhost'

We are going to create mocks to simulate authority answers:

    >>> from unittest.mock import MagicMock
    >>> import requests

    >>> class GetTokenResponse:
    ...     status_code = 200
    ...     def json(self):
    ...         return {
    ...             'accessToken': jwt_result['accessToken'],
    ...             'refreshToken': jwt_result['refreshToken'],
    ...             'status': 'success'
    ...         }
    >>> requests.request = MagicMock(return_value=GetTokenResponse())

    >>> jwt_request = DummyRequest(method='POST', path='/api/auth/jwt/token',
    ...                            params={'login': 'user1', 'password': 'passwd'})
    >>> jwt_request.create_jwt_token = lambda *args, **kwargs: create_jwt_token(jwt_request, *args, **kwargs)
    >>> jwt_request.get_jwt_claims = lambda *args, **kwargs: get_jwt_claims(jwt_request, *args, **kwargs)
    >>> jwt_proxy_result = get_jwt_token(jwt_request)
    >>> pprint.pprint(jwt_proxy_result)
    {'accessToken': 'eyJ...',
     'refreshToken': 'eyJ...',
     'status': 'success'}

Let's check claims from generated token:

    >>> class GetClaimsResponse:
    ...     status_code = 200
    ...     def json(self):
    ...         return {
    ...             'aud': 'app:app1',
    ...             'exp': '...',
    ...             'iat': '...',
    ...             'obj': 'access',
    ...             'sub': 'users:user1'
    ...         }
    >>> requests.request = MagicMock(return_value=GetClaimsResponse())

    >>> jwt_proxy_claims = DummyRequest(authorization=('Bearer', jwt_proxy_result['accessToken']))
    >>> jwt_proxy_claims.get_jwt_claims = lambda *args, **kwargs: get_jwt_claims(jwt_proxy_claims, *args, **kwargs)
    >>> jwt_claims_result = get_jwt_claims(jwt_proxy_claims)
    >>> pprint.pprint(jwt_claims_result)
    {'aud': 'app:app1',
     'exp': '...',
     'iat': '...',
     'obj': 'access',
     'sub': 'users:user1'}

Let's now refresh our access token:

    >>> class GetRefreshResponse:
    ...     status_code = 200
    ...     def json(self):
    ...         return {
    ...             'accessToken': jwt_result['accessToken'],
    ...             'status': 'success'
    ...         }
    >>> requests.request = MagicMock(return_value=GetRefreshResponse())

    >>> jwt_refresh = DummyRequest(authorization=('Bearer', jwt_proxy_result['refreshToken']))
    >>> jwt_refresh.get_jwt_claims = lambda *args, **kwargs: get_jwt_claims(jwt_request, *args, **kwargs)
    >>> jwt_refresh_result = refresh_jwt_token(jwt_refresh)
    >>> pprint.pprint(jwt_refresh_result)
    {'accessToken': 'eyJ...',
     'status': 'success'}


Tests cleanup:

    >>> set_local_registry(None)
    >>> manager.clear()

    >>> tearDown()