import { Controller } from "@hotwired/stimulus"

// Drives both passkey ceremonies. The server does the security-critical work;
// this just shuttles data between the server and the browser's WebAuthn API.
//
// Registration:  POST options -> navigator.credentials.create() -> POST result
// Sign in:       POST options -> navigator.credentials.get()    -> POST result
//
// The options/credential JSON encodes binary fields (challenge, ids, keys) as
// base64url. parseCreationOptionsFromJSON / parseRequestOptionsFromJSON /
// toJSON() convert to and from the ArrayBuffers the raw API wants.
export default class extends Controller {
  static targets = ["email", "nickname", "error", "button"]
  static values = { optionsUrl: String, submitUrl: String, submitMethod: { type: String, default: "POST" }, mode: String }

  connect() {
    if (!window.PublicKeyCredential || !PublicKeyCredential.parseCreationOptionsFromJSON) {
      this.showError("This browser doesn't support passkeys.")
      this.buttonTarget.disabled = true
    }
  }

  async run(event) {
    event.preventDefault()
    this.showError("")
    this.buttonTarget.disabled = true

    try {
      const options = await this.request("POST", this.optionsUrlValue, this.optionsPayload())

      const credential = this.modeValue === "register"
        ? await navigator.credentials.create({ publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options) })
        : await navigator.credentials.get({ publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options) })

      const result = await this.request(this.submitMethodValue, this.submitUrlValue, { credential: credential.toJSON(), ...this.extraPayload() })
      window.Turbo.visit(result.redirect_to)
    } catch (error) {
      // NotAllowedError = user cancelled or the prompt timed out.
      this.showError(error.name === "NotAllowedError" ? "Passkey prompt was cancelled." : error.message)
      this.buttonTarget.disabled = false
    }
  }

  optionsPayload() {
    return this.hasEmailTarget ? { email: this.emailTarget.value } : {}
  }

  extraPayload() {
    return this.hasNicknameTarget ? { nickname: this.nicknameTarget.value } : {}
  }

  async request(method, url, body) {
    const response = await fetch(url, {
      method,
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-CSRF-Token": document.querySelector("meta[name=csrf-token]").content
      },
      body: JSON.stringify(body)
    })
    const data = await response.json().catch(() => ({}))
    if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`)
    return data
  }

  showError(message) {
    this.errorTarget.textContent = message
  }
}
