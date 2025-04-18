Changelog
=========

2.2.1
-----
 - added support for Python 3.12

2.2.0
-----
 - added support for registered JWT client keys
 - added support for ES256, ES384 and ES512 signature algorithms
 - refactored plugin methods decorators

2.1.0
-----
 - replaced 'jwt_object' view predicate with a view deriver to raise
   HTTP Unauthorized error instead of HTTP NotFound

2.0.4
-----
 - added interface adapter check
 - replace `datetime.utcnow` call with `datime.now(timezone.utc)`

2.0.3
-----
 - updated settings configuration keys

2.0.2
-----
 - updated REST API route name and path configuration setting name

2.0.1
-----
 - updated modal forms title

2.0.0
-----
 - upgraded to Pyramid 2.0

1.4.6
-----
 - interfaces cleanup

1.4.5
-----
 - updated Colander API schemas for better OpenAPI specifications

1.4.4
-----
 - updated PyJWT package dependency to 2.6.0
 - added support for Python 3.11

1.4.3
-----
 - added CORS validators to REST services

1.4.2
-----
 - PyAMS_security interfaces refactoring
 - added support for Python 3.10

1.4.1
-----
 - added expiration date (based on refresh token lifetime) to response when generating tokens

1.4.0
-----
 - added REST API to get token from an already authorized principal
 - updated menus context

1.3.1
-----
 - fixed Gitlab-CI Pylint task

1.3.0
-----
 - removed support for Python < 3.5
 - use Colander schemas in JWT REST API

1.2.3
-----
 - updated Gitlab-CI configuration
 - removed Travis-CI configuration

1.2.2
-----
 - Pylint cleanup

1.2.1
-----
 - updated package requirements

1.2.0
-----
 - added support for "proxy" mode, where JWT tokens management is delegated to another
   authentication authority

1.1.2
-----
 - updated french translation

1.1.1
-----
 - doctest update

1.1.0
-----
 - added refresh tokens management with Cornice REST API
 - added JWT configuration management interface

1.0.2
-----
 - updated package description to allow upload to Pypi!

1.0.1
-----
 - removed upload of coverage data to Coveralls.io because of unknown errors

1.0.0
-----
 - initial release
