# Authentication ceremony: prove possession of a previously registered passkey.
#
#   1. options: server issues a fresh random challenge.
#   2. Browser has the authenticator SIGN that challenge (plus the origin and
#      RP ID hash) with the private key, after a biometric/PIN check.
#   3. create: we look up the stored public key by credential id and verify
#      the signature. No secret is ever sent over the wire or stored by us.
class SessionsController < ApplicationController
  allow_unauthenticated_access only: %i[ new options create ]

  def new
    redirect_to root_path if signed_in?
  end

  def options
    # No allowCredentials list: the browser shows the user whichever passkeys
    # it has for this site ("discoverable credentials"), so no username is needed.
    options = WebAuthn::Credential.options_for_get(user_verification: "required")
    session[:authentication_challenge] = options.challenge
    render json: options
  end

  def create
    challenge = session.delete(:authentication_challenge) or
      return render json: { error: "No sign-in in progress" }, status: :unprocessable_content

    passkey = WebAuthn::Credential.from_get(params.require(:credential))
    stored = Credential.find_by!(external_id: passkey.id)

    passkey.verify(
      challenge,
      public_key: stored.public_key,
      sign_count: stored.sign_count,
      user_verification: true
    )

    # The authenticator also returns the user handle it saved at registration.
    unless ActiveSupport::SecurityUtils.secure_compare(passkey.user_handle.to_s, stored.user.webauthn_id)
      raise WebAuthn::Error, "User handle mismatch"
    end

    stored.update!(sign_count: passkey.sign_count)
    sign_in stored.user
    render json: { redirect_to: root_path }
  rescue WebAuthn::Error, ActiveRecord::RecordNotFound
    # Deliberately vague. This also covers a sign counter that went backwards,
    # which can indicate a cloned authenticator.
    render json: { error: "Passkey could not be verified" }, status: :unauthorized
  end

  def destroy
    sign_out
    redirect_to new_session_path, status: :see_other
  end
end
