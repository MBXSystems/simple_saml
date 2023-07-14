defmodule SimpleSaml do
  @moduledoc """
  This library is helper for adding SAML service provider functionality without relying on xmerl
  and thus being vulnerable to [atom exhaustion](https://erlef.github.io/security-wg/secure_coding_and_deployment_hardening/xmerl.html).
  It does so by using the [simple_xml](https://hex.pm/packages/simple_xml), which in turn uses
  [saxy](https://hex.pm/packages/saxy) to generate a string based DOM reprsentation.

  """
end
