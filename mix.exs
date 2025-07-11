defmodule SimpleSaml.MixProject do
  use Mix.Project

  def project do
    [
      app: :simple_saml,
      version: "1.2.0",
      elixir: "~> 1.17",
      start_permanent: Mix.env() == :prod,
      aliases: aliases(),
      dialyzer: dialyzer(),
      description: description(),
      package: package(),
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp description do
    """
    A helper for adding SAML service provider functionality without relying on xmerl.
    """
  end

  defp package do
    [
      files: ~w(lib .formatter.exs mix.exs README* LICENSE* CHANGELOG*),
      licenses: ["MIT"],
      links: %{
        "Changelog" => "https://github.com/MBXSystems/simple_saml/blob/main/CHANGELOG.md",
        "GitHub" => "https://github.com/MBXSystems/simple_saml"
      }
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:simple_xml, "~> 1.3"},
      {:x509, "~> 0.9.0"},
      {:ex_doc, ">= 0.0.0", only: [:dev], runtime: false},
      {:credo, "~> 1.7.0", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.3", only: [:dev, :test], runtime: false}
    ]
  end

  defp dialyzer do
    [
      ignore_warnings: "config/dialyzer.ignore.exs",
      plt_ignore_apps: []
    ]
  end

  defp aliases do
    [
      lint: ["format --check-formatted", "credo --strict", "dialyzer --halt-exit-status"]
    ]
  end
end
