defmodule SimpleSaml do
  @moduledoc """
  This library is a helper for adding SAML service provider functionality without relying on xmerl
  and thus being vulnerable to [atom exhaustion](https://erlef.github.io/security-wg/secure_coding_and_deployment_hardening/xmerl.html).
  It does so by using the [simple_xml](https://hex.pm/packages/simple_xml), which in turn uses
  [saxy](https://hex.pm/packages/saxy) to generate a string based DOM reprsentation.
  """

  alias SimpleSaml.Assertion
  alias SimpleXml.XmlNode

  @type public_key :: {atom(), any()}

  @doc """
  Parses a base 64 encoded SAML Response and returns the corresponding DOM and a struct containing
  the assertion from the response.

  **IMPORTANT**: This function neither verifies the response signature, nor does it validate the
  claims therein.  Use the `verify_and_validate_response/3` function to do those things instead.

  ## Examples

  ### SAML responses are parsed and the DOM + assertion returned

      iex> saml_response = ~S{PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48c2FtbDJwOlJlc3BvbnNlIERlc3RpbmF0aW9uPSJodHRwczovL2xvY2FsLm1ieC5jb206NDAwMS9hdXRoL2FoZWFkL3NzbyIgSUQ9ImlkMjgxNTExODY2NDU1Mzc3NjE0OTUyNTg1NTkiIElzc3VlSW5zdGFudD0iMjAyMy0wNy0xNFQxNzoyMjoyOC4zMjNaIiBWZXJzaW9uPSIyLjAiIHhtbG5zOnNhbWwycD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIj48c2FtbDI6SXNzdWVyIEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOm5hbWVpZC1mb3JtYXQ6ZW50aXR5IiB4bWxuczpzYW1sMj0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiI+aHR0cDovL3d3dy5va3RhLmNvbS9leGthNWhhNmJrblk2T2tkODVkNzwvc2FtbDI6SXNzdWVyPjxkczpTaWduYXR1cmUgeG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPjxkczpTaWduZWRJbmZvPjxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PGRzOlNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZHNpZy1tb3JlI3JzYS1zaGEyNTYiLz48ZHM6UmVmZXJlbmNlIFVSST0iI2lkMjgxNTExODY2NDU1Mzc3NjE0OTUyNTg1NTkiPjxkczpUcmFuc2Zvcm1zPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjZW52ZWxvcGVkLXNpZ25hdHVyZSIvPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48L2RzOlRyYW5zZm9ybXM+PGRzOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jI3NoYTI1NiIvPjxkczpEaWdlc3RWYWx1ZT5Va2EwRWg2eHpZV2VFc3hROFA1eXh0RU1BQndFeEFEMmVuNFdUMW5QQkhFPTwvZHM6RGlnZXN0VmFsdWU+PC9kczpSZWZlcmVuY2U+PC9kczpTaWduZWRJbmZvPjxkczpTaWduYXR1cmVWYWx1ZT5BNUVRRXM2NjN1Ri9NZ0RTNEc0TDJUc0lYYXEvTGZLS1RDNS9wZFdRNm81cHBzeitTWkQ2TmxyL2haamJsZGJ3TFNGN0pXUHVSYVM4cllSUDZHYWg3blV1Rmx2RXNpRVdyRitZbk8ybzdKWHMyaFROckdrKzMyYVBVeWpkaW83TVRBWnFoN1didjFDTCtsV1hnM3cvaW9LTHI1a0Y5aXpMTTBxWDNOMUZ3bnNOdm1lVE1UL2RibGVCVzZiQ3duc0NMNUpFblpqTlBvaUhFRnBOY21kRHBEZUc1Ym5QVnZSUmxIdU1zbXhUU0NyNVoxS09vSUhvZ1Qrdk91VXViYVFnSjNjeC8zTUJyUHlMWFRFaVBtYU81YlNoUVdXNTZ0bU1GekdpUCtkUi8xMGFydVpGbWJlbXNKV21sbzFndmx2Y1VVY3Y0VTMzSWFBdnNtNXlkZUZwZGc9PTwvZHM6U2lnbmF0dXJlVmFsdWU+PGRzOktleUluZm8+PGRzOlg1MDlEYXRhPjxkczpYNTA5Q2VydGlmaWNhdGU+TUlJRHFEQ0NBcENnQXdJQkFnSUdBWWo4bEFZa01BMEdDU3FHU0liM0RRRUJDd1VBTUlHVU1Rc3dDUVlEVlFRR0V3SlZVekVUTUJFRwpBMVVFQ0F3S1EyRnNhV1p2Y201cFlURVdNQlFHQTFVRUJ3d05VMkZ1SUVaeVlXNWphWE5qYnpFTk1Bc0dBMVVFQ2d3RVQydDBZVEVVCk1CSUdBMVVFQ3d3TFUxTlBVSEp2ZG1sa1pYSXhGVEFUQmdOVkJBTU1ER1JsZGkwME5UTTBPVGt3TmpFY01Cb0dDU3FHU0liM0RRRUoKQVJZTmFXNW1iMEJ2YTNSaExtTnZiVEFlRncweU16QTJNamN4TVRFM05UbGFGdzB6TXpBMk1qY3hNVEU0TlRsYU1JR1VNUXN3Q1FZRApWUVFHRXdKVlV6RVRNQkVHQTFVRUNBd0tRMkZzYVdadmNtNXBZVEVXTUJRR0ExVUVCd3dOVTJGdUlFWnlZVzVqYVhOamJ6RU5NQXNHCkExVUVDZ3dFVDJ0MFlURVVNQklHQTFVRUN3d0xVMU5QVUhKdmRtbGtaWEl4RlRBVEJnTlZCQU1NREdSbGRpMDBOVE0wT1Rrd05qRWMKTUJvR0NTcUdTSWIzRFFFSkFSWU5hVzVtYjBCdmEzUmhMbU52YlRDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQwpnZ0VCQUxURTdJUkcrb1FaQkFTUTdEWTN5ZVRyd0FCZEkyQmdHMkZYS1NrVFBrOWVuTXd0eVV5RFhDT3RlT2cxOCsvL01BMlVUdmdTCkkrbjBmaUFoN0JpN2N4cGltbk9hai9rY2d2cGRuKzV3cEVmU0lES0FlRWc5VklRZjBmei9rczRYa3JOeFJoOGJhNloveXBPVlIyVEwKb3p1OHY2c2pHQ2lxSFNvaVBsNzhLSU5IeDlqTUIzUUdkVEhSeHNUendGUEdjVUV2TzdYdmp4eE1OOUZMWmRIa3d0QTZjWlhEYkhsQQp2K280RWJMSVJxWEZjM3ZGNXJzM0Z6K2NncVozSFZHbTkwVEZGY2JQYngvZUtjdnp5SGRZdDhQNXBpMzY0bWlqdDlOS3ROVjlGOVZkClB6K0dwL3J4bHcwaS9JV3hWMC92QnJXMTBIUGQ0Mmtyc09nSGlieEJZZzhDQXdFQUFUQU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUEKcnBZelpFb1ljUm8zWUY3Tnk0Z2RjOE9EU2xQUEtJZEx2d2hVVEdiUGR6SlUyaWZ4ekUvS2VUSEdtRnBqcGFrakRtbVdzcjJqOUZHVQovOVUwU2pxUG1KSFA1Z1liam16K3REM2plYUVrSUJEWnBjWWMrTXZlUWFBN3VETUlMQTJPVWhIdUZ1MFVKVmpHeGwyRUlweGl2QytJCkowUnBCUzVBRVJUNlY5MUZxdjJZbHdiNXNrbGhvWEdEeDlzK2wrVWQxTUxhZXdJdm5VSGRJUnRDMDJidmxoand0MHBuSUNEdEhNaWsKdk9pVFhqVEJKZ2w3WDlRNTFHbTYzNnE5cEpWalMxVDBnUjNjTnQ5SkpFL2ZvRGRPSzhKb3pSRnRGNGoxNHhlZ1hMdDdCVkJJWHVTTwpLNlAxYzA5bUNQUTFWSmJjajAxUzF6ZnJ2WitSWnZyeHIvMGFYUT09PC9kczpYNTA5Q2VydGlmaWNhdGU+PC9kczpYNTA5RGF0YT48L2RzOktleUluZm8+PC9kczpTaWduYXR1cmU+PHNhbWwycDpTdGF0dXMgeG1sbnM6c2FtbDJwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiPjxzYW1sMnA6U3RhdHVzQ29kZSBWYWx1ZT0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnN0YXR1czpTdWNjZXNzIi8+PC9zYW1sMnA6U3RhdHVzPjxzYW1sMjpBc3NlcnRpb24gSUQ9ImlkMjgxNTExODY2NDU2OTg4NDUyMDY4NDg3ODE0IiBJc3N1ZUluc3RhbnQ9IjIwMjMtMDctMTRUMTc6MjI6MjguMzIzWiIgVmVyc2lvbj0iMi4wIiB4bWxuczpzYW1sMj0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiI+PHNhbWwyOklzc3VlciBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpuYW1laWQtZm9ybWF0OmVudGl0eSI+aHR0cDovL3d3dy5va3RhLmNvbS9leGthNWhhNmJrblk2T2tkODVkNzwvc2FtbDI6SXNzdWVyPjxzYW1sMjpTdWJqZWN0PjxzYW1sMjpOYW1lSUQgRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoxLjE6bmFtZWlkLWZvcm1hdDp1bnNwZWNpZmllZCI+ZGouamFpbjwvc2FtbDI6TmFtZUlEPjxzYW1sMjpTdWJqZWN0Q29uZmlybWF0aW9uIE1ldGhvZD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmNtOmJlYXJlciI+PHNhbWwyOlN1YmplY3RDb25maXJtYXRpb25EYXRhIE5vdE9uT3JBZnRlcj0iMjAyMy0wNy0xNFQxNzoyNzoyOC4zMjRaIiBSZWNpcGllbnQ9Imh0dHBzOi8vbG9jYWwubWJ4LmNvbTo0MDAxL2F1dGgvYWhlYWQvc3NvIi8+PC9zYW1sMjpTdWJqZWN0Q29uZmlybWF0aW9uPjwvc2FtbDI6U3ViamVjdD48c2FtbDI6Q29uZGl0aW9ucyBOb3RCZWZvcmU9IjIwMjMtMDctMTRUMTc6MTc6MjguMzI0WiIgTm90T25PckFmdGVyPSIyMDIzLTA3LTE0VDE3OjI3OjI4LjMyNFoiPjxzYW1sMjpBdWRpZW5jZVJlc3RyaWN0aW9uPjxzYW1sMjpBdWRpZW5jZT54cU81MkNORUxkMGhWQjl2YVgxZF9kY3d1WUF4R1VTcjwvc2FtbDI6QXVkaWVuY2U+PC9zYW1sMjpBdWRpZW5jZVJlc3RyaWN0aW9uPjwvc2FtbDI6Q29uZGl0aW9ucz48c2FtbDI6QXV0aG5TdGF0ZW1lbnQgQXV0aG5JbnN0YW50PSIyMDIzLTA3LTE0VDE3OjIyOjI4LjMyM1oiIFNlc3Npb25JbmRleD0iaWQxNjg5MzU1MzQ4MzIyLjM1NTAxMzgiPjxzYW1sMjpBdXRobkNvbnRleHQ+PHNhbWwyOkF1dGhuQ29udGV4dENsYXNzUmVmPnVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphYzpjbGFzc2VzOlBhc3N3b3JkUHJvdGVjdGVkVHJhbnNwb3J0PC9zYW1sMjpBdXRobkNvbnRleHRDbGFzc1JlZj48L3NhbWwyOkF1dGhuQ29udGV4dD48L3NhbWwyOkF1dGhuU3RhdGVtZW50Pjwvc2FtbDI6QXNzZXJ0aW9uPjwvc2FtbDJwOlJlc3BvbnNlPg==}
      iex> {:ok, {_root, assertion}} = SimpleSaml.parse_response(saml_response)
      iex> assertion
      %SimpleSaml.Assertion{
        issuer: "http://www.okta.com/exka5ha6bknY6Okd85d7",
        name_id: "dj.jain",
        name_id_not_on_or_after: ~U[2023-07-14 17:27:28.324Z],
        recipient: "https://local.mbx.com:4001/auth/ahead/sso",
        not_before: ~U[2023-07-14 17:17:28.324Z],
        not_on_or_after: ~U[2023-07-14 17:27:28.324Z],
        audience: "xqO52CNELd0hVB9vaX1d_dcwuYAxGUSr"
      }

  """
  @spec parse_response(String.t()) ::
          {:ok, {SimpleXml.xml_node(), Assertion.t()}} | {:error, any()}
  def parse_response(base64_encoded_saml_response) do
    with {:ok, saml_body} <- base64_encoded_saml_response |> Base.decode64(),
         {:ok, root_node} <- SimpleXml.parse(saml_body),
         {:ok, assertion_node} <- XmlNode.first_child(root_node, ~r/.*:?Assertion$/),
         {:ok, %Assertion{} = assertion} <- Assertion.from_node(assertion_node) do
      {:ok, {root_node, assertion}}
    else
      :error -> {:error, :base64_decoding_failed}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  This function verifies the digest and signature of the XML document using the given public key.
  It also validates that the timestamp constraints within the assertion are still valid.

  **IMPORTANT**: Before you rely on the claims made within the assertion, you must validate that the
  `issuer`, `recipient`, and `audience` field values in the assertion match your expected value.
  This helps to thwart an attack where a SAML response intended for a different audience or target
  endpoint is reused with your endpoint.
  """
  @spec verify_and_validate_response(SimpleXml.xml_node(), Assertion.t(), public_key()) ::
          :ok | {:error, any()}
  def verify_and_validate_response(root_node, %Assertion{} = assertion, public_key) do
    with :ok <- SimpleXml.verify(root_node, public_key),
         :ok <- Assertion.validate_time_conditions(assertion) do
      :ok
    else
      {:error, reason} -> {:error, reason}
    end
  end
end
