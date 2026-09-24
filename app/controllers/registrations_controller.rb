# Registration ceremony: create a new account and its first passkey.
#
#   1. options: server picks a random challenge, remembers it in the session.
#   2. Browser asks the authenticator to make a new key pair for this RP.
#      The private key never leaves the device.
#   3. create: browser sends back the new PUBLIC key + a signature over our
#      challenge. We verify it and store the public key.
class RegistrationsController < ApplicationController
  include PasskeyCreation

  allow_unauthenticated_access

  def new
  end

  def options
    user = User.new(email: params[:email])

    # A signed-out visitor must never be able to attach a new passkey to an
    # existing account, or they could take it over. Adding passkeys to an
    # existing account should require being signed in.
    unless user.valid?
      return render json: { error: user.errors.full_messages.to_sentence }, status: :unprocessable_content
    end

    options = creation_options_for(user)

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

    passkey = verified_passkey(pending["challenge"])

    user = User.new(email: pending["email"], webauthn_id: pending["webauthn_id"])
    User.transaction do
      user.save!
      user.credentials.create!(credential_attributes_for(passkey))
    end

    sign_in user
    render json: { redirect_to: root_path }
  rescue WebAuthn::Error, ActiveRecord::RecordInvalid => error
    render json: { error: error.message }, status: :unprocessable_content
  end
end
