require "test_helper"

class PasskeyResetsTest < ActionDispatch::IntegrationTest
  setup do
    register "eric@example.com"
    @user = User.find_by!(email: "eric@example.com")
    @old_credential = @user.credentials.first
    delete session_path
    @new_device = WebAuthn::FakeClient.new(PasskeyHelpers::ORIGIN)
  end

  test "emailed link lets the user replace their passkeys from a new device" do
    perform_enqueued_jobs do
      post passkey_resets_path, params: { email: "eric@example.com" }
    end
    assert_redirected_to new_session_path

    mail = ActionMailer::Base.deliveries.last
    assert_equal [ "eric@example.com" ], mail.to
    token = mail.text_part.body.to_s[%r{/passkey_resets/([^/\s]+)/edit}, 1]
    assert token.present?

    get edit_passkey_reset_path(token)
    assert_response :success

    reset_with @new_device, token
    assert_response :success
    assert_equal @user.id, session[:user_id]

    assert_equal 1, @user.credentials.reload.count
    assert_not_equal @old_credential.external_id, @user.credentials.first.external_id
    assert_not Credential.exists?(@old_credential.id)
  end

  test "the old passkey no longer signs in, and the new one does" do
    token = @user.generate_token_for(:passkey_reset)
    reset_with @new_device, token
    delete session_path

    post options_session_path, as: :json
    post session_path, params: { credential: assertion_for(@user, response.parsed_body["challenge"]) }, as: :json
    assert_response :unauthorized

    post options_session_path, as: :json
    post session_path, params: { credential: assertion_for(@user, response.parsed_body["challenge"], client: @new_device) }, as: :json
    assert_response :success
  end

  test "a reset link cannot be used twice" do
    token = @user.generate_token_for(:passkey_reset)
    reset_with @new_device, token
    assert_response :success
    delete session_path

    get edit_passkey_reset_path(token)
    assert_redirected_to new_passkey_reset_path

    post options_passkey_reset_path(token), as: :json
    assert_response :unprocessable_content
  end

  test "an expired link is rejected" do
    token = @user.generate_token_for(:passkey_reset)

    travel 16.minutes do
      get edit_passkey_reset_path(token)
      assert_redirected_to new_passkey_reset_path
    end
  end

  test "a garbage token is rejected" do
    get edit_passkey_reset_path("nope")
    assert_redirected_to new_passkey_reset_path

    post options_passkey_reset_path("nope"), as: :json
    assert_response :unprocessable_content
  end

  test "a failed verification leaves the existing passkeys untouched" do
    token = @user.generate_token_for(:passkey_reset)
    post options_passkey_reset_path(token), as: :json
    forged = @new_device.create(challenge: WebAuthn.generate_user_id, user_verified: true)

    patch passkey_reset_path(token), params: { credential: forged }, as: :json
    assert_response :unprocessable_content
    assert_equal [ @old_credential.id ], @user.credentials.reload.ids
    assert_nil session[:user_id]
  end

  test "requesting a reset for an unknown email looks the same and sends nothing" do
    assert_no_enqueued_jobs do
      post passkey_resets_path, params: { email: "nobody@example.com" }
    end

    assert_redirected_to new_session_path
    assert_equal "If that email has an account, we've sent a link to reset your passkey.", flash[:notice]
  end

  private
    def reset_with(client, token)
      post options_passkey_reset_path(token), as: :json
      assert_response :success
      credential = client.create(challenge: response.parsed_body["challenge"], user_verified: true)

      patch passkey_reset_path(token), params: { credential: credential }, as: :json
    end
end
