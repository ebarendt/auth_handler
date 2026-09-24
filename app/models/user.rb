class User < ApplicationRecord
  has_many :credentials, dependent: :destroy

  normalizes :email, with: ->(email) { email.strip.downcase }

  validates :email, presence: true, uniqueness: true,
                    format: { with: URI::MailTo::EMAIL_REGEXP }

  # The "user handle": an opaque, random, stable ID the authenticator stores
  # alongside each passkey. It must NOT be the email or database id, since it
  # can be returned to a site during discoverable-credential login.
  before_validation :set_webauthn_id, on: :create

  private
    def set_webauthn_id
      self.webauthn_id ||= WebAuthn.generate_user_id
    end
end
