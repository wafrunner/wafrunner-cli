# Configuring the CLI

The `configure` command group allows you to manage the settings for `wafrunner-cli`.

## Setting Your API Key

The most important configuration is setting your API key, which is required to authenticate with the wafrunner platform.

### Interactive Prompt

The easiest way to set your key is to run the command without any arguments. You will be prompted to enter your key securely:

```sh
wafrunner configure set-api-key
```

The CLI will hide your input for security.

### Non-Interactive (via Option)

You can also provide the key directly as an option. This is useful for scripting and automated environments.

```sh
wafrunner configure set-api-key --api-key YOUR_SECRET_API_KEY
```