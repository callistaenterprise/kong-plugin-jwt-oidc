# kong-plugin-jwt-oidc

**kong-plugin-jwt-oidc** is an Open Source plugin for [Kong](https://github.com/Mashape/kong) which restricts
access based on a JWT access token. It is similar to (but more capable than) the
[jwt](https://docs.konghq.com/hub/kong-inc/jwt/) built-in plugin.

The implementation of this plugin was heavily inspired by/based on the
[jwt-keycloak](https://github.com/telekom-digioss/kong-plugin-jwt-keycloak) plugin.

## Install

Install luarocks and run the following command

```sh
    luarocks install kong-plugin-jwt-oidc
```

You also need to set the KONG_PLUGINS environment variable

```sh
    export KONG_PLUGINS=...,jwt-oidc
```

## Configuration

To enable the plugin for a service:

```sh
    curl -X POST http://localhost:8001/services/{ID}/plugins \
        --data "name=jwt-oidc"  \
        --data "config.allowed_iss=http://keycloak.local.net/realms/test"
```

To enable the plugin using declarative config in `kong.yml`:

```kong.conf
    ...
    plugins: 
    - name: mtls-auth
      config:
        allowed_iss:
        - http://keycloak.local.net/realms/test
```

### Plugin Priority

In some cases you might want to change the execution priority of the plugin. You can do that by setting an environmental variable: `JWT_OIDC_PRIORITY="900"`.

### jwt Parameters

The following parameters from the standard Kong bundled jwt plugin are reused:

| Parameter            | Requied | Default         | Description |
| -------------------- | ------- | ----------------| ----------- |
| `header_names`       | no      | `authorization` | A list of HTTP header names that Kong will inspect to retrieve JWTs. |
| `uri_param_names`    | no      | `jwt`           | A list of querystring parameters that Kong will inspect to retrieve JWTs. |
| `cookie_names`       | no      |                 | A list of cookie names that Kong will inspect to retrieve JWTs. |
| `claims_to_verify`   | no      | `exp`           | A list of registered claims (according to [RFC 7519](https://tools.ietf.org/html/rfc7519)) that Kong can verify as well. Accepted values: `exp`, `nbf`.  |
| `run_on_preflight`   | no      | `true`          | A boolean value that indicates whether the plugin should run (and try to authenticate) on `OPTIONS` preflight requests, if set to false then `OPTIONS` requests will always be allowed. |
| `maximum_expiration` | no      | `0`             | An integer limiting the lifetime of the JWT to `maximum_expiration` seconds in the future. Any JWT that has a longer lifetime will be rejected (HTTP 403). If this value is specified, `exp` must be specified as well in the `claims_to_verify` property. The default value of `0` represents an indefinite period. Potential clock skew should be considered when configuring this value. |
| `algorithm`          | no      | `RS256`         | The algorithm used to verify the token’s signature. Can be `HS256`, `HS384`, `HS512`, `RS256`, or `ES256`. |

### Parameters

The following additional parameters are used:

| Parameter                         | Requied | Default           | Description |
| --------------------------------- | ------- | ----------------- | ----------- |
| `allowed_iss`                     | yes     |                   |A list of allowed issuers for this route/service/api. Can be specified as a string or as a [Pattern](http://lua-users.org/wiki/PatternsTutorial).|
| `iss_key_grace_period`            | no      | 10                | An integer that sets the number of seconds until public keys for an issuer can be updated after writing new keys to the cache. This is a guard so that the Kong cache will not invalidate every time a token signed with an invalid public key is sent to the plugin. |
| `allowed_aud`                     | no      |                   | A list of allowed audiences for this route/service/api. |
| `jwks_uri_template`               | no      |                   | A string template that the jwks endpoint for the IDP is created from (used if `well_known` uri isn't available). String formatting is applied on the template and `%s` is replaced by the issuer of the token. Example: `"%s/discovery/keys"` |
| `well_known_template`             | no      | *see description* | A string template that the well known endpoint for keycloak is created from (used to lookup the jwks_uri if `jwks_uri_template` is not set). String formatting is applied on the template and `%s` is replaced by the issuer of the token. Default value is `%s/.well-known/openid-configuration` |
| `ssl_verify`                      | yes     | `true`            | A boolean value that indicates if the plugin should verify issuer server certificate validity when retrieving issuer keys. Default true, set it to false in test scenarios where issuers use self-signed certificates |
| `scope`                           | no      |                   | A list of scopes the token must have to access the api, i.e. `["email"]`. The token only has to have one of the listed scopes to be authorized. |
| `consumer_match`                  | yes     | `false`           | A boolean value that indicates if the plugin should find a kong consumer with `id`/`custom_id` that equals the `consumer_match_claim` claim in the access token. |
| `consumer_match_claim`            | no      | `azp`             | The claim name in the token that the plugin will try to match the kong `id`/`custom_id` against. |
| `consumer_match_claim_custom_id`  | no      | `false`           | A boolean value that indicates if the plugin should match the `consumer_match_claim` claim against the consumers `id` or `custom_id`. By default it matches the consumer against the `id`. |
| `consumer_match_ignore_not_found` | no      | `false`           | A boolean value that indicates if the request should be let through regardless if the plugin is able to match the request to a kong consumer or not. |
| `allow_anonymous`                 | yes     | `false`           | Flag to allow/block anonymous clients. |
| `upstream_claim_headers`          | no      | `["scope"]`       | List of claims to expose as headers to upstream api. |
| `upstream_claim_header_prefix`    | no      | `X-`              | Header name prefix for claims exposed as headers to upstream api. |

## Upstream context

The plugin appends the following variables to the global context, to allow subsequent plugins to access them:

| Header                                    | Description             |
|-------------------------------------------|-------------------------|
| `kong.ctx.shared.jwt_oidc_token`          | The validated jwt token |

## Upstream headers

The plugin appends the following headers to the request before proxying it to the upstream API.

| Header                 | Description                                                                  |
|------------------------|------------------------------------------------------------------------------|
| `X-Consumer-ID`        | The authenticated consumer ID (set if `consumer_match` is true)              |
| `X-Consumer-Custom-ID` | The authenticated consumer custom-ID (set if `consumer_match` is true)       |
| `X-Consumer-Username`  | The authenticated consumer username (set if `consumer_match` is true)        |
| `X-Anonymous-Consumer` | Set to `true` for anonymous requests (requires `allow_anonymous` to be true) |
| `X-<claim>`            | Set for each claim configured in `upstream_claim_headers`                    |

## Caveats

To verify token issuers, this plugin needs to be able to access the `<ISSUER_REALM_URL>/.well-known/openid-configuration` and corresponding `jwks_uri` endpoint of the issuer. If you are getting the error `{ "message": "Unable to get public key for issuer" }` it is probably because for some reason the plugin is unable to access one of these endpoints.

## License

Licensed under the Apache License, Version 2.0
