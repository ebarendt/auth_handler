Rails.application.routes.draw do
  get "up" => "rails/health#show", as: :rails_health_check

  # Each passkey ceremony is two round trips:
  #   POST .../options  -> server issues a random challenge + parameters
  #   POST ...          -> browser returns the signed result; server verifies it
  resource :registration, only: %i[ new create ] do
    post :options, on: :collection
  end

  resource :session, only: %i[ new create destroy ] do
    post :options, on: :collection
  end

  resources :passkey_resets, param: :token, only: %i[ new create edit update ] do
    post :options, on: :member
  end

  root "home#show"
end
