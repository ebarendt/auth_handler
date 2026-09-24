# Registration ceremony: create a new account and its first passkey.
#
#   1. options: server picks a random challenge, remembers it in the session.
#   2. Browser asks the authenticator to make a new key pair for this RP.
#      The private key never leaves the device.
#   3. create: browser sends back the new PUBLIC key + a signature over our
#      challenge. We verify it and store the public key.
class RegistrationsController < ApplicationController
  allow_unauthenticated_access

  def new
  end

  def options
    user = User.new(email: params[:email])
    user.validate

    # A signed-out visitor must never be able to attach a new passkey to an
    # existing account, or they could take it over. Adding passkeys to an
    # existing account should require being signed in.
    if user.errors.any?
      return render json: { error: user.errors.full_messages.to_sentence }, status: :unprocessable_content
    end

    options = WebAuthn::Credential.options_for_create(
      user: { id: user.webauthn_id, name: user.email },
      authenticator_selection: { resident_key: "required", user_verification: "required" }
    )

    # Keep the challenge server-side; the client can't be trusted to hand back
    # the right one. Nothing is written to the database until verification.
    session[:registration] = {
      "challenge" => options.challenge,
      "email" => user.email,
      "webauthn_id" => user.webauthn_id
    }

    render json: options
  end

  def create
    pending = session.delete(:registration) or
      return render json: { error: "No registration in progress" }, status: :unprocessable_content

    passkey = WebAuthn::Credential.from_create(params.require(:credential))
    passkey.verify(pending["challenge"], user_verification: true)

    user = User.new(email: pending["email"], webauthn_id: pending["webauthn_id"])
    User.transaction do
      user.save!
      user.credentials.create!(
        external_id: passkey.id,
        public_key: passkey.public_key,
        sign_count: passkey.sign_count,
        nickname: params[:nickname].presence
      )
    end

    sign_in user
    render json: { redirect_to: root_path }
  rescue WebAuthn::Error, ActiveRecord::RecordInvalid => error
    render json: { error: error.message }, status: :unprocessable_content
  end
end
