# SimpleSaml

[![Build Status](https://github.com/MBXSystems/simple_saml/workflows/CI/badge.svg)](https://github.com/MBXSystems/simple_saml/actions)
[![Module Version](https://img.shields.io/hexpm/v/simple_saml.svg)](https://hex.pm/packages/simple_saml)
[![Hex Docs](https://img.shields.io/badge/hex-docs-lightgreen.svg)](https://hexdocs.pm/simple_saml/)
[![Total Download](https://img.shields.io/hexpm/dt/simple_saml.svg)](https://hex.pm/packages/simple_saml)
[![License](https://img.shields.io/hexpm/l/simple_saml.svg)](https://github.com/MBXSystems/simple_saml/blob/master/LICENSE)
[![Last Updated](https://img.shields.io/github/last-commit/MBXSystems/simple_saml.svg)](https://github.com/MBXSystems/simple_saml/commits/master)

A simplified Elixir string-based XML processor that avoids the atom exhaustion vulnerability present with xmerl based parsers.  It does so by using the `SimpleForm` DOM reprsentation generated by [saxy](https://hex.pm/packages/saxy) library.  Unlike `:xmerl`, this representation only uses strings for all details about the XML document.

This library adds some basic operations for traversing the XML document and obtaining attributes and text values.

## Usage

### Parsing

Parsing is as straightforward as invoking the following command:

```elixir
> SimpleSaml.parse(~S{<foo a="1">bar</foo>})
{:ok, {"foo", [{"a", "1"}], ["bar"]}}
```

See `SimpleSaml.parse/1` for details.

### Digest and Signature Verification

XML digests and signatures can be verified via the following function.

```elixir
> SimpleSaml.verify(root, public_key)
```

We leave it up to the caller to provide the public key against which verify the signature.  Please see `SimpleSaml.verify/2` documentation for detailed examples.

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