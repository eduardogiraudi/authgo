package handlers

type AuthorizeRequest struct{
    Confirmation     bool `json:"confirmation"`
}
type RegisterRequest struct{
    Username     string `json:"username"`
    Email     string `json:"email"`
    Password     string `json:"password"`
    CaptchaValue string `json:"captchaValue"`
}
type RevokeRequest struct {
    Token           string `json:"token"`
    TokenTypeHint   string `json:"token_type_hint,omitempty"` 
}
type OTPRequest struct{
    OTP     string `json:"otp"`
}
type VerifyOTP struct{
    UserID string `json:"user_id"`
    Fingerprint string `json:"fingerprint"`
    QueueID string `json:"queue_id"`
    OTP string `json:"otp"`
}
type LoginRequest struct {
    Username     string `json:"username"`
    Password     string `json:"password"`
    CaptchaValue string `json:"captchaValue"`
}
type TokenRequest struct {
    GrantType    string `json:"grant_type"`
    ClientID     string `json:"client_id,omitempty"`
    ClientSecret string `json:"client_secret,omitempty"`
    Code         string `json:"code,omitempty"`
    RedirectURI  string `json:"redirect_uri,omitempty"`
    CodeVerifier string `json:"code_verifier,omitempty"`
}