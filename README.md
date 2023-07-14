# SimpleSaml

[![Build Status](https://github.com/MBXSystems/simple_saml/workflows/CI/badge.svg)](https://github.com/MBXSystems/simple_saml/actions)
[![Module Version](https://img.shields.io/hexpm/v/simple_saml.svg)](https://hex.pm/packages/simple_saml)
[![Hex Docs](https://img.shields.io/badge/hex-docs-lightgreen.svg)](https://hexdocs.pm/simple_saml/)
[![Total Download](https://img.shields.io/hexpm/dt/simple_saml.svg)](https://hex.pm/packages/simple_saml)
[![License](https://img.shields.io/hexpm/l/simple_saml.svg)](https://github.com/MBXSystems/simple_saml/blob/master/LICENSE)
[![Last Updated](https://img.shields.io/github/last-commit/MBXSystems/simple_saml.svg)](https://github.com/MBXSystems/simple_saml/commits/master)

This library is a helper for adding SAML service provider functionality without relying on xmerl and thus being vulnerable to [atom exhaustion](https://erlef.github.io/security-wg/secure_coding_and_deployment_hardening/xmerl.html). It does so by using the [simple_xml](https://hex.pm/packages/simple_xml), which in turn uses [saxy](https://hex.pm/packages/saxy) to generate a string based DOM reprsentation.

## Usage

### SAML Response

```elixir
# Parse a SAML response.
{:ok, {root, %Assertion{} = assertion}} = SimpleSaml.parse_response(saml_response)

# Identify the IDP based on the audience within the asserion and obtain the associated parameters: issuer (e.g. "http://www.okta.com/exka5ha6bknY6Okd85d7"), audience (i.e. a fix string your application provided to the IDP), and the SAML certificate of the IDP

# SAML certificates are typically stored in PEM or Der format.  Here's an example of how to obtain the public key using the X509 library:
# Assume cert_pem contains the string contents of the certificate pem file
{:ok, cert} = X509.Certificate.from_pem(cert_pem)
public_key = X509.Certificate.public_key(cert)

# Use the public key to verify and validate
:ok = SimpleSaml.verify_and_validate_response(root, assertion, public_key)

# Validate that assertion.issuer, assertion.recipient values match your expected values for the IDP

# At this point, you're ready to use the assertion.name_id claim within your application to
# authenticate the user.
```

## Installation

The package can be installed, via [Hex](https://hex.pm/packages/simple_saml), by adding `simple_saml` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:simple_saml, "~> 1.0.0"}
  ]
end
```

## Contributing

We welcome merge requests for fixing issues or expanding functionality.

Clone and compile with:

```shell
git clone https://github.com/MBXSystems/simple_saml.git
cd simple_saml
mix deps.get
mix compile
```

Verify that tests and linting pass with your changes.

```shell
mix test
mix lint
```

All code changes should be accompanied with unit tests.

## License

MIT License

Copyright (c) 2023 AHEAD, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
