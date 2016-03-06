.. coding=utf-8

Authentication tools for micro-services in Djanto REST Framework
================================================================

Provides JWT-based authentication tools useful for building micro-services with Django Rest Framework.

This allows a loosely decoupled authentication structure, where user login and account creation/management are managed by an external server.  We only require that the authentication server is able to issue JWT authentication tokens.  Then, each micro-service will take a valid JWT and map it 1-to-1 to a local user account (creating this account the first time a user is encountered).  The users are uniquely identified by a UUID that is included in the JWT payload under the 'uid' field.
