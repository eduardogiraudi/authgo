package routes

import (
    "auth/cryptokeys"
    "encoding/json"
    "net/http"
    "os"
    "auth/responses"
)

func OpenIDConfiguration(w http.ResponseWriter, r *http.Request) {
    domain := os.Getenv("AUTH_SERVER_DOMAIN")
    
    config := map[string]interface{}{
        "issuer":                 domain,
        "authorization_endpoint": domain + "/authorize",
        "token_endpoint":         domain + "/token",
        "userinfo_endpoint":      domain + "/userinfo",
        "jwks_uri":               domain + "/.well-known/jwks.json",
        "response_types_supported": []string{"code"}, 
        "grant_types_supported":    []string{"authorization_code", "client_credentials"},
        "id_token_signing_alg_values_supported": []string{"ES512"},
        "dpop_signing_alg_values_supported":     []string{"ES512", "ES256"},
        "registration_endpoint":         domain + "/register_client",
        "subject_types_supported": []string{"public"},
        "scopes_supported": []string{"openid", "profile", "email", "address", "phone"},
        "dpop_required": true,
        "dpop_algorithms_supported": []string{"ES512", "ES256"},

    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(config)
}

func JWKSHandler(w http.ResponseWriter, r *http.Request) {
    jwks, err := cryptokeys.GetJWKS()
    if err != nil {
        responses.ServerError(w)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(jwks)
}