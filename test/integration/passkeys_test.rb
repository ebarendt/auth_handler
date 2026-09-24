require "test_helper"

# Uses WebAuthn::FakeClient to play the role of browser + authenticator, so
# these tests exercise the real challenge/signature verification end to end.
class PasskeysTest < ActionDispatch::IntegrationTest
  ORIGIN = "http://localhost:3000"

  setup do
    @client = WebAuthn::FakeClient.new(ORIGIN)
  end

  test "register, sign out, then sign in with the passkey" do
    register "eric@example.com"
    user = User.find_by!(email: "eric@example.com")
    assert_equal 1, user.credentials.count

    get root_path
    assert_response :success

    delete session_path
    get root_path
    assert_redirected_to new_session_path

    sign_in_with_passkey user
    assert_response :success
    assert_equal user.id, session[:user_id]
  end

  test "registration rejects an email that is already taken" do
    register "eric@example.com"
    delete session_path

    post options_registration_path, params: { email: "eric@example.com" }, as: :json
    assert_response :unprocessable_content
  end

  test "registration rejects a signature over the wrong challenge" do
    post options_registration_path, params: { email: "eric@example.com" }, as: :json
    forged = @client.create(challenge: WebAuthn.generate_user_id, user_verified: true)

    assert_no_difference "User.count" do
      post registration_path, params: { credential: forged }, as: :json
    end
    assert_response :unprocessable_content
  end

  test "registration requires user verification" do
    post options_registration_path, params: { email: "eric@example.com" }, as: :json
    credential = @client.create(challenge: response.parsed_body["challenge"], user_verified: false)

    assert_no_difference "User.count" do
      post registration_path, params: { credential: credential }, as: :json
    end
    assert_response :unprocessable_content
  end

  test "a signed assertion cannot be replayed" do
    register "eric@example.com"
    user = User.find_by!(email: "eric@example.com")
    delete session_path

    post options_session_path, as: :json
    assertion = assertion_for(user, response.parsed_body["challenge"])

    post session_path, params: { credential: assertion }, as: :json
    assert_response :success

    delete session_path
    post session_path, params: { credential: assertion }, as: :json
    assert_response :unprocessable_content # challenge was single-use and is gone
    assert_nil session[:user_id]
  end

  test "sign in fails for an unknown passkey" do
    stranger = WebAuthn::FakeClient.new(ORIGIN)
    stranger.create(challenge: WebAuthn.generate_user_id, user_verified: true)

    post options_session_path, as: :json
    assertion = stranger.get(challenge: response.parsed_body["challenge"], user_verified: true)

    post session_path, params: { credential: assertion }, as: :json
    assert_response :unauthorized
  end

  test "sign in fails when the assertion comes from a different origin" do
    register "eric@example.com"
    user = User.find_by!(email: "eric@example.com")
    delete session_path

    # Same authenticator, but the browser reports a phishing site's origin.
    phisher = WebAuthn::FakeClient.new("https://evil.example", authenticator: @client.send(:authenticator))
    post options_session_path, as: :json
    assertion = phisher.get(
      challenge: response.parsed_body["challenge"], rp_id: "localhost",
      user_verified: true, user_handle: raw_handle(user)
    )

    post session_path, params: { credential: assertion }, as: :json
    assert_response :unauthorized
  end

  test "sign in fails when the user handle does not match the credential's owner" do
    register "eric@example.com"
    user = User.find_by!(email: "eric@example.com")
    delete session_path

    post options_session_path, as: :json
    assertion = @client.get(
      challenge: response.parsed_body["challenge"], user_verified: true, user_handle: "someone-else"
    )

    post session_path, params: { credential: assertion }, as: :json
    assert_response :unauthorized
    assert_nil session[:user_id]
  end

  test "protected pages redirect to sign in" do
    get root_path
    assert_redirected_to new_session_path
  end

  private
    def register(email)
      post options_registration_path, params: { email: email }, as: :json
      assert_response :success
      credential = @client.create(challenge: response.parsed_body["challenge"], user_verified: true)

      post registration_path, params: { credential: credential, nickname: "Test key" }, as: :json
      assert_response :success
    end

    def sign_in_with_passkey(user)
      post options_session_path, as: :json
      assert_response :success

      post session_path, params: { credential: assertion_for(user, response.parsed_body["challenge"]) }, as: :json
      assert_response :success
      get root_path
    end

    def assertion_for(user, challenge)
      @client.get(challenge: challenge, user_verified: true, user_handle: raw_handle(user))
    end

    # The authenticator stores the raw bytes of the id we sent (base64url-decoded
    # by the browser), and returns those bytes as the userHandle.
    def raw_handle(user)
      WebAuthn.standard_encoder.decode(user.webauthn_id)
    end
end
