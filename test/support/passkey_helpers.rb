module PasskeyHelpers
  extend ActiveSupport::Concern

  ORIGIN = "http://localhost:3000"

  included do
    setup { @client = WebAuthn::FakeClient.new(ORIGIN) }
  end

  private
    def register(email, client: @client)
      post options_registration_path, params: { email: email }, as: :json
      assert_response :success
      credential = client.create(challenge: response.parsed_body["challenge"], user_verified: true)

      post registration_path, params: { credential: credential, nickname: "Test key" }, as: :json
      assert_response :success
    end

    def assertion_for(user, challenge, client: @client)
      client.get(challenge: challenge, user_verified: true, user_handle: raw_handle(user))
    end

    def raw_handle(user)
      WebAuthn.standard_encoder.decode(user.webauthn_id)
    end
end
