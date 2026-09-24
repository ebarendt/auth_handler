module PasskeyCreation
  extend ActiveSupport::Concern

  private
    def creation_options_for(user)
      WebAuthn::Credential.options_for_create(
        user: { id: user.webauthn_id, name: user.email },
        authenticator_selection: { resident_key: "required", user_verification: "required" }
      )
    end

    def verified_passkey(challenge)
      WebAuthn::Credential.from_create(params.require(:credential)).tap do |passkey|
        passkey.verify(challenge, user_verification: true)
      end
    end

    def credential_attributes_for(passkey)
      {
        external_id: passkey.id,
        public_key: passkey.public_key,
        sign_count: passkey.sign_count,
        nickname: params[:nickname].presence
      }
    end
end
