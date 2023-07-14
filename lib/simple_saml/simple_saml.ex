defmodule SimpleSaml do
  @moduledoc """
  This library is helper for adding SAML service provider functionality without relying on xmerl
  and thus being vulnerable to [atom exhaustion](https://erlef.github.io/security-wg/secure_coding_and_deployment_hardening/xmerl.html).
  It does so by using the [simple_xml](https://hex.pm/packages/simple_xml), which in turn uses
  [saxy](https://hex.pm/packages/saxy) to generate a string based DOM reprsentation.

  """

  alias SimpleSaml.Assertion
  alias SimpleXml.XmlNode

  @type public_key :: {atom(), any()}

  @spec parse_response(String.t()) ::
          {:ok, {SimpleXml.xml_node(), Assertion.t()}} | {:error, any()}
  def parse_response(base64_encoded_saml_response) do
    with {:ok, saml_body} <- base64_encoded_saml_response |> Base.decode64(),
         {:ok, root_node} <- SimpleXml.parse(saml_body),
         {:ok, assertion_node} <- XmlNode.first_child(root_node, "*:Assertion"),
         {:ok, %Assertion{} = assertion} <- Assertion.from_node(assertion_node) do
      {:ok, {root_node, assertion}}
    else
      :error -> {:error, :base64_decoding_failed}
      {:error, reason} -> {:error, reason}
    end
  end

  @spec verify_and_validate_response(String.t(), public_key()) ::
          {:ok, Assertion.t()} | {:error, any()}
  def verify_and_validate_response(base64_encoded_saml_response, public_key) do
    with {:ok, {root_node, assertion}} <- parse_response(base64_encoded_saml_response),
         :ok <- verify_and_validate_response(root_node, assertion, public_key) do
      {:ok, assertion}
    else
      {:error, reason} -> {:error, reason}
    end
  end

  def verify_and_validate_response(root_node, %Assertion{} = assertion, public_key) do
    with :ok <- SimpleXml.verify(root_node, public_key),
         :ok <- Assertion.validate_time_conditions(assertion) do
      :ok
    else
      {:error, reason} -> {:error, reason}
    end
  end
end
