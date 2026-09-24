# The Relying Party (RP) is this app. Passkeys are cryptographically bound to
# the RP ID (a domain), so a passkey made for this site is useless on a
# phishing site — the browser simply won't offer it there.
WebAuthn.configure do |config|
  # Origins the browser may report in clientDataJSON. Must match exactly
  # (scheme + host + port). localhost is treated as a secure context.
  config.allowed_origins = ENV.fetch("WEBAUTHN_ORIGINS", "http://localhost:3000").split(",")

  # RP ID defaults to the host of the origin; set it explicitly in production.
  config.rp_id = ENV["WEBAUTHN_RP_ID"] if ENV["WEBAUTHN_RP_ID"]

  config.rp_name = "Auth Handler"
end
