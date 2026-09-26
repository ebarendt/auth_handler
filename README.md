# Auth Handler

A small Rails app built to learn how passkeys (WebAuthn) work by implementing
them end to end. It is a learning project, not a production auth system.

There are no passwords. Accounts are created with a passkey, you sign in with
a passkey, and a lost passkey is replaced through an emailed reset link.

## What it covers

- **Registration**: create an account with an email and a new passkey.
- **Sign in**: usernameless. The browser offers whichever passkeys it has for
  this site (discoverable credentials), so no email is asked for.
- **Passkey reset**: request an emailed link, then register a new passkey.
  Completing a reset removes the account's old passkeys and signs you in.

Each passkey ceremony is two round trips: the server issues a random challenge
(`.../options`), the authenticator signs it, and the server verifies the
result. The private key never leaves the user's device. The server only stores
the public key, so there is no secret to steal.

## How it is built

- Rails 8.1, Ruby 4.0.6, SQLite, importmap, Turbo and Stimulus.
- The [`webauthn`](https://github.com/cedarcode/webauthn-ruby) gem does the
  cryptographic verification.
- `app/javascript/controllers/passkey_controller.js` calls the browser's
  `navigator.credentials` API and shuttles data to the server.
- `RegistrationsController`, `SessionsController` and `PasskeyResetsController`
  implement the three flows. `PasskeyCreation` holds the logic shared by
  registration and reset.
- `User` has many `Credential`s. A user's `webauthn_id` is a random, opaque
  handle that the authenticator stores. It is not the email or database id.
- Sessions are a plain signed cookie (`Authentication` concern).
- Reset links use Rails' `generates_token_for`: they expire after 15 minutes
  and stop working once the account's passkeys change, so they are single use.
  Reset requests are rate limited and never reveal whether an email has an
  account.

## Running it

```sh
bin/setup
```

That installs gems, prepares the database and starts the dev server. Use
`bin/setup --skip-server` to set up without starting it, then `bin/rails server`.

Use `http://localhost:3000`, not `127.0.0.1`. A passkey is bound to its exact
host, so one registered on `localhost` will not match another host.

In development, emails are written to `tmp/mails/` instead of being sent. Open
the file there to find the reset link.

```sh
bin/rails test
bin/rubocop
bin/brakeman
```

The tests use `WebAuthn::FakeClient` as a stand-in browser and authenticator,
so they exercise real challenge and signature verification without a browser.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `WEBAUTHN_ORIGINS` | `http://localhost:3000` | Comma-separated origins the browser may report. Must match exactly (scheme, host and port). |
| `WEBAUTHN_RP_ID` | host of the origin | The relying party ID, a domain. Set it explicitly in production. |

## Gotchas found along the way

- **1Password and Turbo.** The sign-in, registration and reset pages set
  `<meta name="turbo-visit-control" content="reload">` so they always load as
  a full page. After a Turbo body swap (for example, logging out and back in)
  the 1Password extension in Firefox did not take over the passkey prompt.
- **`json` is pinned below 3.** Rails 8.1.3.1 calls `JSON.parse` with a
  positional options hash that json 3.x removed, which breaks JSON request
  bodies. Remove the pin once Rails fixes it.
- **`sign_count` is usually 0.** Synced passkeys (1Password, iCloud Keychain,
  Google Password Manager) always report 0. The clone-detection check mostly
  matters for hardware keys.

## Not built

- Adding, listing or removing passkeys for a signed-in account.
- Server-side session revocation. Sessions are cookie-only, so a reset cannot
  sign out a stolen, still-logged-in browser.
- Attestation. The gem supports it, but it is left off.
- Production mail and host settings. `ApplicationMailer` still uses the
  placeholder `from@example.com`, and production needs real SMTP settings and
  a real host in `default_url_options`.
