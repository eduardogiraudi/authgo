package routes

import (
	"net/http"
	"auth/handlers"
    "auth/middleware"

)
func SetupRoutes(mux *http.ServeMux) {
    

    //TODO
    mux.HandleFunc("POST /register", middleware.RequireJSONParams(handlers.Register, "username","email", "password", "captchaValue"))
    mux.HandleFunc("POST /introspect",handlers.Userinfo)
    //DONE BUT NEEDS NEW FEATURES
    mux.HandleFunc("POST /token",middleware.RequireJSONParams(handlers.Token, "grant_type"))
    //DONE
    mux.HandleFunc("POST /forgot_password", middleware.RequireJSONParams(handlers.ForgotPassword, "email", "captchaValue"))
    mux.HandleFunc("POST /change_password_with_otp",middleware.RequireJSONParams(handlers.ChangePasswordWithOTP, "newPassword", "otp", "captchaValue", "id"))
    
    
    
    mux.HandleFunc("POST /change_password_with_token",middleware.RequireJSONParams(middleware.Protected(handlers.ChangePasswordWithToken, false), "password","new_password", "captchaValue"))
    mux.HandleFunc("POST /revoke",middleware.RequireJSONParams(middleware.Protected(handlers.Revoke, false), "token"))
    mux.HandleFunc("POST /logout",middleware.Protected(handlers.Logout, false))
    mux.HandleFunc("POST /refresh_token",middleware.Protected(handlers.Refresh, true))
    mux.HandleFunc("GET /userinfo",middleware.Protected(handlers.Userinfo, false)) 
    mux.HandleFunc("POST /otp", middleware.RequireJSONParams(handlers.Otp, "otp"))
    mux.HandleFunc("POST /authorize", middleware.RequireJSONParams(handlers.Authorize, "confirmation"))
    mux.HandleFunc("GET /scope_details", handlers.ScopeDetails)
    mux.HandleFunc("GET /authorize", middleware.ValidateOAuthArgs("authorize",middleware.RequireArgs([]string{"client_id","response_type","redirect_uri","scope"},handlers.ServeStatic)))
    mux.HandleFunc("POST /login", middleware.RequireJSONParams(handlers.Login, "username", "password", "captchaValue"))
    mux.HandleFunc("GET /", middleware.ValidateOAuthArgs("login",middleware.RequireArgs([]string{"client_id","response_type","redirect_uri","scope"},handlers.ServeStatic)))
    mux.HandleFunc("GET /login", middleware.ValidateOAuthArgs("login",middleware.RequireArgs([]string{"client_id","response_type","redirect_uri","scope"},handlers.ServeStatic)))
    mux.HandleFunc("GET /register", middleware.ValidateOAuthArgs("login",middleware.RequireArgs([]string{"client_id","response_type","redirect_uri","scope"},handlers.ServeStatic)))
    mux.HandleFunc("GET /forgot_password", middleware.ValidateOAuthArgs("login",middleware.RequireArgs([]string{"client_id","response_type","redirect_uri","scope"},handlers.ServeStatic)))
    mux.HandleFunc("GET /change_password_with_otp", middleware.ValidateOAuthArgs("login",middleware.RequireArgs([]string{"client_id","response_type","redirect_uri","scope"},handlers.ServeStatic)))
    mux.HandleFunc("GET /assets/{path...}", handlers.ServeStatic)
    mux.HandleFunc("GET /.well-known/openid-configuration", handlers.OpenIDConfiguration)
    mux.HandleFunc("GET /.well-known/oauth-authorization-server", handlers.OpenIDConfiguration)
    mux.HandleFunc("GET /.well-known/jwks.json", handlers.JWKSHandler)
    mux.HandleFunc("GET /jwks", handlers.JWKSHandler)
    mux.HandleFunc("GET /pow", handlers.GetCaptchaChallenge)
}
