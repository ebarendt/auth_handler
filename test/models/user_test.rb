require "test_helper"

class UserTest < ActiveSupport::TestCase
  test "generates an opaque webauthn_id distinct from email and id" do
    user = User.create!(email: "a@example.com")

    assert user.webauthn_id.present?
    assert_not_equal user.email, user.webauthn_id
  end

  test "normalizes email and enforces uniqueness" do
    User.create!(email: "  A@Example.com ")

    assert_equal "a@example.com", User.last.email
    assert_not User.new(email: "a@example.com").valid?
  end
end
