class PasskeyResetMailer < ApplicationMailer
  def reset(user)
    @user = user
    @token = user.generate_token_for(:passkey_reset)

    mail to: user.email, subject: "Reset your passkey"
  end
end
