class PasskeyResetsController < ApplicationController
  include PasskeyCreation

  allow_unauthenticated_access
  rate_limit to: 5, within: 1.minute, only: :create,
             with: -> { redirect_to new_passkey_reset_path, alert: "Too many requests. Please try again in a minute." }
  before_action :set_user, only: %i[ edit options update ]

  def new
  end

  def create
    if (user = User.find_by(email: params[:email]))
      PasskeyResetMailer.reset(user).deliver_later
    end

    redirect_to new_session_path, notice: "If that email has an account, we've sent a link to reset your passkey."
  end

  def edit
  end

  def options
    options = creation_options_for(@user)
    session[:passkey_reset_challenge] = options.challenge
    render json: options
  end

  def update
    challenge = session.delete(:passkey_reset_challenge) or
      return render json: { error: "No reset in progress" }, status: :unprocessable_content

    passkey = verified_passkey(challenge)

    User.transaction do
      @user.credentials.destroy_all
      @user.credentials.create!(credential_attributes_for(passkey))
    end

    sign_in @user
    render json: { redirect_to: root_path }
  rescue WebAuthn::Error, ActiveRecord::RecordInvalid => error
    render json: { error: error.message }, status: :unprocessable_content
  end

  private
    def set_user
      @user = User.find_by_token_for(:passkey_reset, params[:token])
      return if @user

      respond_to do |format|
        format.html { redirect_to new_passkey_reset_path, alert: "That reset link is invalid or has expired." }
        format.json { render json: { error: "That reset link is invalid or has expired." }, status: :unprocessable_content }
      end
    end
end
