module Authentication
  extend ActiveSupport::Concern

  included do
    before_action :require_authentication
    helper_method :current_user, :signed_in?
  end

  class_methods do
    def allow_unauthenticated_access(**options)
      skip_before_action :require_authentication, **options
    end
  end

  private
    def current_user
      @current_user ||= User.find_by(id: session[:user_id]) if session[:user_id]
    end

    def signed_in?
      current_user.present?
    end

    def require_authentication
      redirect_to new_session_path unless signed_in?
    end

    def sign_in(user)
      # Fresh session on privilege change prevents session fixation.
      reset_session
      session[:user_id] = user.id
    end

    def sign_out
      reset_session
    end
end
