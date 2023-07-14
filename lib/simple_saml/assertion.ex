defmodule SimpleSaml.Assertion do
  @moduledoc """
  A struct for representing a SAML assertion.

  Use `from_node/1` to instantiate an `Assertion` from an XML node.  Then use
  `validate_time_conditions/1` to validate that the time constraints within the assertion are still
  valid.

  **__IMPORTANT__**: It is up to the user of the assertion to validate the issuer, recipient and
  audience fields based on (typically) stored records about the part making the assertion.
  """
  alias SimpleXml.XmlNode

  @type xml_node :: SimpleXml.xml_node()

  defstruct issuer: nil,
            name_id: nil,
            name_id_not_on_or_after: nil,
            recipient: nil,
            not_before: nil,
            not_on_or_after: nil,
            audience: nil

  @type t :: %__MODULE__{
          issuer: String.t(),
          name_id: String.t(),
          name_id_not_on_or_after: DateTime.t(),
          recipient: String.t(),
          not_before: DateTime.t(),
          not_on_or_after: DateTime.t(),
          audience: String.t()
        }

  @doc """
  Given an assertion XML node, this function returns an Assertion struct that represents the data
  within the node.

  Note that this function does not validate the conditions within the assertion.  Use
  `validate_time_conditions/1` for checking that the assertion's time constraints are still valid.

  ## Examples

  ### Assertion can be loaded from XML

      iex> xml = ~S{<saml2:Assertion ID="id2812939747337372346813126" IssueInstant="2023-07-14T12:16:55.216Z" Version="2.0" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"><saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">http://www.okta.com/exka5ha6bknY6Okd85d7</saml2:Issuer><saml2:Subject><saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">dj.jain</saml2:NameID><saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml2:SubjectConfirmationData NotOnOrAfter="2023-07-14T12:21:55.216Z" Recipient="https://local.mbx.com:4001/auth/ahead/sso"/></saml2:SubjectConfirmation></saml2:Subject><saml2:Conditions NotBefore="2023-07-14T12:11:55.216Z" NotOnOrAfter="2023-07-14T12:21:55.216Z"><saml2:AudienceRestriction><saml2:Audience>xqO52CNELd0hVB9vaX1d_dcwuYAxGUSr</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions><saml2:AuthnStatement AuthnInstant="2023-07-14T12:16:55.216Z" SessionIndex="id1689337015214.1284590967"><saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef></saml2:AuthnContext></saml2:AuthnStatement></saml2:Assertion>}
      iex> {:ok, assertion_node} = SimpleXml.parse(xml)
      iex> SimpleSaml.Assertion.from_node(assertion_node)
      {:ok,
      %SimpleSaml.Assertion{
        issuer: "http://www.okta.com/exka5ha6bknY6Okd85d7",
        name_id: "dj.jain",
        name_id_not_on_or_after: ~U[2023-07-14 12:21:55.216Z],
        recipient: "https://local.mbx.com:4001/auth/ahead/sso",
        not_before: ~U[2023-07-14 12:11:55.216Z],
        not_on_or_after: ~U[2023-07-14 12:21:55.216Z],
        audience: "xqO52CNELd0hVB9vaX1d_dcwuYAxGUSr"
      }}

  ### An error is generated if a field is missing

      iex> xml = ~S{<saml2:Assertion ID="id2812939747337372346813126" IssueInstant="2023-07-14T12:16:55.216Z" Version="2.0" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"><saml2:Subject><saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">dj.jain</saml2:NameID><saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml2:SubjectConfirmationData NotOnOrAfter="2023-07-14T12:21:55.216Z" Recipient="https://local.mbx.com:4001/auth/ahead/sso"/></saml2:SubjectConfirmation></saml2:Subject><saml2:Conditions NotBefore="2023-07-14T12:11:55.216Z" NotOnOrAfter="2023-07-14T12:21:55.216Z"><saml2:AudienceRestriction><saml2:Audience>xqO52CNELd0hVB9vaX1d_dcwuYAxGUSr</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions><saml2:AuthnStatement AuthnInstant="2023-07-14T12:16:55.216Z" SessionIndex="id1689337015214.1284590967"><saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef></saml2:AuthnContext></saml2:AuthnStatement></saml2:Assertion>}
      iex> {:ok, assertion_node} = SimpleXml.parse(xml)
      iex> {:error, {:child_not_found, [child_name: "*:Issuer", actual_children: _]}} = SimpleSaml.Assertion.from_node(assertion_node)

  """
  @spec from_node(xml_node()) :: {:ok, t()} | {:error, any()}
  def from_node(xml_node) when is_tuple(xml_node) do
    with {:ok, issuer_node} <- XmlNode.first_child(xml_node, "*:Issuer"),
         {:ok, issuer} <- XmlNode.text(issuer_node),
         {:ok, subject_node} <- XmlNode.first_child(xml_node, "*:Subject"),
         {:ok, name_id_node} <- XmlNode.first_child(subject_node, "*:NameID"),
         {:ok, name_id} <- XmlNode.text(name_id_node),
         {:ok, {name_id_not_on_or_after, recipient}} <- get_subject_confirmation(subject_node),
         {:ok, conditions_node} <- XmlNode.first_child(xml_node, "*:Conditions"),
         {:ok, not_before_string} <- XmlNode.attribute(conditions_node, "NotBefore"),
         {:ok, not_before} <- to_datetime(not_before_string),
         {:ok, not_on_or_after_string} <- XmlNode.attribute(conditions_node, "NotOnOrAfter"),
         {:ok, not_on_or_after} <- to_datetime(not_on_or_after_string),
         {:ok, audience_restriction_node} <-
           XmlNode.first_child(conditions_node, "*:AudienceRestriction"),
         {:ok, audience_node} <- XmlNode.first_child(audience_restriction_node, "*:Audience"),
         {:ok, audience} <- XmlNode.text(audience_node) do
      {:ok,
       %__MODULE__{
         issuer: issuer,
         name_id: name_id,
         name_id_not_on_or_after: name_id_not_on_or_after,
         recipient: recipient,
         not_before: not_before,
         not_on_or_after: not_on_or_after,
         audience: audience
       }}
    else
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Validates that the timestamp constraints within the given assertion are still valid.

  ## Examples

  ### Assertion can be loaded from XML

      iex> xml = ~S{<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"><saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">http://www.okta.com/exka5ha6bknY6Okd85d7</saml2:Issuer><saml2:Subject><saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">dj.jain</saml2:NameID><saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml2:SubjectConfirmationData NotOnOrAfter="3000-07-14T12:21:55.216Z" Recipient="https://local.mbx.com:4001/auth/ahead/sso"/></saml2:SubjectConfirmation></saml2:Subject><saml2:Conditions NotBefore="2023-07-14T12:11:55.216Z" NotOnOrAfter="3000-07-14T12:21:55.216Z"><saml2:AudienceRestriction><saml2:Audience>xqO52CNELd0hVB9vaX1d_dcwuYAxGUSr</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions><saml2:AuthnStatement AuthnInstant="2023-07-14T12:16:55.216Z" SessionIndex="id1689337015214.1284590967"><saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef></saml2:AuthnContext></saml2:AuthnStatement></saml2:Assertion>}
      iex> {:ok, assertion_node} = SimpleXml.parse(xml)
      iex> {:ok, assertion} = SimpleSaml.Assertion.from_node(assertion_node)
      iex> SimpleSaml.Assertion.validate_time_conditions(assertion)
      :ok

  ### Validation fails if `name_id_not_on_or_after` matches or is before current time.

      iex> xml = ~s{<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"><saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">http://www.okta.com/exka5ha6bknY6Okd85d7</saml2:Issuer><saml2:Subject><saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">dj.jain</saml2:NameID><saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml2:SubjectConfirmationData NotOnOrAfter="2023-07-14T16:13:18.963Z" Recipient="https://local.mbx.com:4001/auth/ahead/sso"/></saml2:SubjectConfirmation></saml2:Subject><saml2:Conditions NotBefore="2023-07-14T12:11:55.216Z" NotOnOrAfter="3000-07-14T12:21:55.216Z"><saml2:AudienceRestriction><saml2:Audience>xqO52CNELd0hVB9vaX1d_dcwuYAxGUSr</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions><saml2:AuthnStatement AuthnInstant="2023-07-14T12:16:55.216Z" SessionIndex="id1689337015214.1284590967"><saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef></saml2:AuthnContext></saml2:AuthnStatement></saml2:Assertion>}
      iex> {:ok, assertion_node} = SimpleXml.parse(xml)
      iex> {:ok, assertion} = SimpleSaml.Assertion.from_node(assertion_node)
      iex> SimpleSaml.Assertion.validate_time_conditions(assertion)
      {:error, :assertion_validation_failed}

  ### Validation fails if `not_before` is after the current time.

      iex> xml = ~S{<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"><saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">http://www.okta.com/exka5ha6bknY6Okd85d7</saml2:Issuer><saml2:Subject><saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">dj.jain</saml2:NameID><saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml2:SubjectConfirmationData NotOnOrAfter="3000-07-14T12:21:55.216Z" Recipient="https://local.mbx.com:4001/auth/ahead/sso"/></saml2:SubjectConfirmation></saml2:Subject><saml2:Conditions NotBefore="3000-07-14T12:11:55.216Z" NotOnOrAfter="3000-07-14T12:21:55.216Z"><saml2:AudienceRestriction><saml2:Audience>xqO52CNELd0hVB9vaX1d_dcwuYAxGUSr</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions><saml2:AuthnStatement AuthnInstant="2023-07-14T12:16:55.216Z" SessionIndex="id1689337015214.1284590967"><saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef></saml2:AuthnContext></saml2:AuthnStatement></saml2:Assertion>}
      iex> {:ok, assertion_node} = SimpleXml.parse(xml)
      iex> {:ok, assertion} = SimpleSaml.Assertion.from_node(assertion_node)
      iex> SimpleSaml.Assertion.validate_time_conditions(assertion)
      {:error, :assertion_validation_failed}

  ### Validation fails if `not_on_or_after` matches or is before the current time.

      iex> xml = ~S{<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"><saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">http://www.okta.com/exka5ha6bknY6Okd85d7</saml2:Issuer><saml2:Subject><saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">dj.jain</saml2:NameID><saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml2:SubjectConfirmationData NotOnOrAfter="3000-07-14T12:21:55.216Z" Recipient="https://local.mbx.com:4001/auth/ahead/sso"/></saml2:SubjectConfirmation></saml2:Subject><saml2:Conditions NotBefore="2023-07-14T12:11:55.216Z" NotOnOrAfter="2000-07-14T12:21:55.216Z"><saml2:AudienceRestriction><saml2:Audience>xqO52CNELd0hVB9vaX1d_dcwuYAxGUSr</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions><saml2:AuthnStatement AuthnInstant="2023-07-14T12:16:55.216Z" SessionIndex="id1689337015214.1284590967"><saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef></saml2:AuthnContext></saml2:AuthnStatement></saml2:Assertion>}
      iex> {:ok, assertion_node} = SimpleXml.parse(xml)
      iex> {:ok, assertion} = SimpleSaml.Assertion.from_node(assertion_node)
      iex> SimpleSaml.Assertion.validate_time_conditions(assertion)
      {:error, :assertion_validation_failed}
  """
  @spec validate_time_conditions(t()) :: :ok | {:error, any()}
  def validate_time_conditions(
        %__MODULE__{
          name_id_not_on_or_after: %DateTime{} = name_id_not_on_or_after,
          not_before: %DateTime{} = not_before,
          not_on_or_after: %DateTime{} = not_on_or_after
        } = _assertion
      ) do
    with current_time <- DateTime.utc_now(),
         :lt <- DateTime.compare(current_time, name_id_not_on_or_after),
         :gt <- DateTime.compare(current_time, not_before),
         :lt <- DateTime.compare(current_time, not_on_or_after) do
      :ok
    else
      _ ->
        {:error, :assertion_validation_failed}
    end
  end

  @spec get_subject_confirmation(xml_node()) ::
          {:ok, {DateTime.t(), String.t()}} | {:error, any()}
  defp get_subject_confirmation(subject_node) when is_tuple(subject_node) do
    with {:ok, subject_confirmation_node} <-
           XmlNode.first_child(subject_node, "*:SubjectConfirmation"),
         {:ok, method} <- XmlNode.attribute(subject_confirmation_node, "Method"),
         :ok <- verify_bearer_confirmation_method(method),
         {:ok, subject_confirmation_data_node} <-
           XmlNode.first_child(subject_confirmation_node, "*:SubjectConfirmationData"),
         {:ok, not_before_or_after_string} <-
           XmlNode.attribute(subject_confirmation_data_node, "NotOnOrAfter"),
         {:ok, not_before_or_after} <- to_datetime(not_before_or_after_string),
         {:ok, recipient} <- XmlNode.attribute(subject_confirmation_data_node, "Recipient") do
      {:ok, {not_before_or_after, recipient}}
    else
      {:error, reason} -> {:error, reason}
    end
  end

  @spec verify_bearer_confirmation_method(String.t()) :: :ok | {:error, any()}
  defp verify_bearer_confirmation_method("urn:oasis:names:tc:SAML:2.0:cm:bearer"), do: :ok

  defp verify_bearer_confirmation_method(method),
    do: {:error, {:unsupported_subject_confirmation_method, method}}

  @spec to_datetime(String.t()) :: {:ok, DateTime.t()} | {:error, any()}
  defp to_datetime(iso8601_datetime) when is_binary(iso8601_datetime) do
    case DateTime.from_iso8601(iso8601_datetime) do
      {:ok, %DateTime{} = datetime, _} ->
        {:ok, datetime}

      {:error, _reason} ->
        {:error, {:failed_to_parse_timestamp, iso8601_datetime}}
    end
  end
end
