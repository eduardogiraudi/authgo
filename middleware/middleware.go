package middleware

import (
    "auth/responses"
    "fmt"
    "io"
    "encoding/json"
    "auth/cryptokeys"
    "bytes"
    "os"
    "net/http"
    "strings"
    "github.com/altcha-org/altcha-lib-go"
    //"go.mongodb.org/mongo-driver/mongo"
    "auth/db"
        "auth/utils"
    "slices"
    "context"
    "time"
    "go.mongodb.org/mongo-driver/bson"
    "regexp"
    "auth/jwts"
    "go.mongodb.org/mongo-driver/bson/primitive"
    "github.com/google/uuid"
    "net/url"

)
func normalizeURI(uri string) string {
    return strings.TrimSuffix(uri, "/")
}
var supported_scope = []string{"openid", "profile", "email", "address", "phone"}
func RequireArgs(argNames []string, next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        query := r.URL.Query()
        var missingArgs []string

        for _, arg := range argNames {
            if query.Get(arg) == "" {
                missingArgs = append(missingArgs, arg)
            }
        }

        if len(missingArgs) > 0 {
            descr := fmt.Sprintf("Missing required arguments: %s", strings.Join(missingArgs, ", "))
            responses.BadRequest(w, "invalid_request", descr)
            return
        }

        next(w, r)
    }
}

func RequireJSONParams(next http.HandlerFunc, params ...string) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        bodyBytes, err := io.ReadAll(r.Body)
        if err != nil {
            responses.BadRequest(w, "invalid_request", "Error reading body")
            return
        }
        r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

        var data map[string]interface{}
        if err := json.Unmarshal(bodyBytes, &data); err != nil {
            responses.BadRequest(w, "invalid_request", "Invalid JSON format")
            return
        }

        var missing []string
        for _, p := range params {
            if _, ok := data[p]; !ok {
                missing = append(missing, p)
            }
        }

        if len(missing) > 0 {
            descr := fmt.Sprintf("Missing required parameters: %s", strings.Join(missing, ", "))
            responses.BadRequest(w, "invalid_request", descr)
            return
        }

        next(w, r)
    }
}

func RequireFormParams(next http.HandlerFunc, params ...string) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        if err := r.ParseForm(); err != nil {
            responses.BadRequest(w, "invalid_request", "Error parsing form data")
            return
        }

        var missing []string
        for _, p := range params {
            if r.FormValue(p) == "" {
                missing = append(missing, p)
            }
        }

        if len(missing) > 0 {
            descr := fmt.Sprintf("Missing required form data: %s", strings.Join(missing, ", "))
            responses.BadRequest(w, "invalid_request", descr)
            return
        }

        next(w, r)
    }
}

func CaptchaRequired(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        bodyBytes, err := io.ReadAll(r.Body)
        if err != nil {
            responses.BadRequest(w, "invalid_request", "Error reading body")
            return
        }
        r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

        var data struct {
            CaptchaValue string `json:"captchaValue"` 
        }
        if err := json.Unmarshal(bodyBytes, &data); err != nil || data.CaptchaValue == "" {
            responses.BadRequest(w, "captcha_required", "Altcha payload is missing or invalid")
            return
        }


        secret := os.Getenv("ALTCHA_HMAC_KEY")
        
        isValid, err := altcha.VerifySolution(data.CaptchaValue, secret, true)

        if err != nil || !isValid {
            responses.BadRequest(w, "captcha_failed", "Altcha validation failed")
            return
        }

        next(w, r)
    }
}

type SessionData struct {
    ClientId string `json "client_id"`
    RedirectURI string `json "redirect_uri"`
    Scope string `json "scope"`
    State string `json "state"`
    ResponseType string `json "response_type"`
    CodeChallengeMethod string `json "code_challenge_method"`
    CodeChallenge string `json "code_challenge"`
    Step string `json "step"`
    Nonce string `json:"nonce,omitempty"`
}

func ValidateOAuthArgs(step string, next http.HandlerFunc) http.HandlerFunc{
    return func(w http.ResponseWriter, r *http.Request) {
        cookie, errtok := r.Cookie("session_token")
        client_id := r.URL.Query().Get("client_id")
        rawRedirectURI := r.URL.Query().Get("redirect_uri")
        code_challenge_method := r.URL.Query().Get("code_challenge_method")
        code_challenge := r.URL.Query().Get("code_challenge")
        response_type := r.URL.Query().Get("response_type")
        nonce := r.URL.Query().Get("nonce")
        state := r.URL.Query().Get("state")
        collection := db.MongoDB.Collection("clients") 
        scope :=r.URL.Query().Get("scope")
        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()
        var client bson.M
        errcli := collection.FindOne(ctx, bson.M{"client_id": client_id}).Decode(&client)
        uris, ok := client["authorized_redirects"].(primitive.A)
        if !ok {
            responses.BadRequest(w, "invalid_client", "Redirect URIs not configured")
            return
        }
        if code_challenge !="" && code_challenge_method == "" {
            responses.BadRequest(w, "invalid_code_challenge", "Invalid code challenge")
            return
        }
        if code_challenge == "" && code_challenge_method!= "" {
            responses.BadRequest(w, "invalid_code_method", "Invalid code method")
            return
        }
        if code_challenge_method != "" && code_challenge_method != "s256" && code_challenge_method != "S256"{
            responses.BadRequest(w, "unsupported_code_challenge_method", "Unsupported code challenge method")
            return
        }
        if errcli != nil {
            responses.BadRequest(w, "invalid_client", "Invalid client")
            return
        }
        
        found := false
        for _, v := range uris {
            if strVal, ok := v.(string); ok {
                if normalizeURI(strVal) == normalizeURI(rawRedirectURI) {
                    found = true
                    break
                }
            }
        }

        if !found {
            responses.BadRequest(w, "invalid_redirect_uri", "The redirect URI provided does not match any allowed URIs.")
            return
        }
        if response_type != "code" {
            responses.BadRequest(w, "unsupported_response_type", "Unsupported response type")
            return
        }
        requestedScopes := strings.Fields(scope)
        for _, s := range requestedScopes {
        if !slices.Contains(supported_scope, s) {
            responses.BadRequest(w, "unsupported_scope", fmt.Sprintf("Scope '%s' is not supported", s))
            return
            }
        }
        if state != "" {
            var stateRegex = regexp.MustCompile(`^[a-zA-Z0-9-_~.]+$`)
            if len(state)<8{
                responses.BadRequest(w, "invalid_state", "State parameter is too short")
                return
            }
            if !stateRegex.MatchString(state) {
                responses.BadRequest(w, "invalid_state", "State contains invalid characters")
                return
            }
        }

        if errtok != nil {
            var secure bool = true
            jti := uuid.New().String()
            iat := time.Now().UTC()
            exp := iat.Add(time.Minute*10)
            if os.Getenv("DEV_MODE")!=""{
                secure = false
            }
            var session SessionData 
            session.ClientId = client_id
            session.RedirectURI = rawRedirectURI
            session.Scope = scope
            if nonce != ""{
                session.Nonce = nonce
            }
            session.State = state
            session.ResponseType = response_type
            session.CodeChallengeMethod = code_challenge_method
            session.CodeChallenge = code_challenge
            session.Step = "login"
            sessionBytes, err := json.Marshal(session)
            if err != nil {
                responses.ServerError(w)
                return
            }
            errredis:=db.RDB.Set(ctx, jti, sessionBytes, exp.Sub(time.Now())).Err()
            if errredis!=nil{
                fmt.Printf("Error during setting setting session data on Redis:%v\n",errredis)
                responses.ServerError(w)
                return
            }
            claims := jwts.MapClaims{
                "iat": iat,
                "exp": exp.Unix(),
                "jti": jti,
            }
            token, errjwt := jwts.CreateToken(claims,nil)
            if errjwt != nil {
                    responses.ServerError(w)
            }
            authDomainRaw := os.Getenv("AUTH_SERVER_DOMAIN")
            parsedDomain, _ := url.Parse(authDomainRaw)
            cookieDomain := parsedDomain.Hostname()
            newcookie := &http.Cookie{
            Name:     "session_token",
            Value:    token,
            Path:     "/",
            Domain:   cookieDomain,
            MaxAge:   600, 
            HttpOnly: true, 
            Secure:   secure, 
            SameSite: http.SameSiteLaxMode,
            }
            http.SetCookie(w, newcookie)
            if step != "login" {
                authURL := os.Getenv("AUTH_SERVER_DOMAIN") + "/login?" + r.URL.RawQuery
                http.Redirect(w, r, authURL, http.StatusSeeOther)
                return 
            }
        }else{
            token, validatetokerr := jwts.ValidateToken(cookie.Value)
            if validatetokerr == nil && token.Valid {
                claims := token.Claims.(jwts.MapClaims)
                jti := claims["jti"].(string)
                val, err := db.RDB.Get(ctx, jti).Result()
                if err != nil {
                    authDomainRaw := os.Getenv("AUTH_SERVER_DOMAIN")
                    parsedDomain, _ := url.Parse(authDomainRaw)
                    
                    http.SetCookie(w, &http.Cookie{
                        Name:     "session_token",
                        Value:    "",
                        Path:     "/",
                        Domain:   parsedDomain.Hostname(),
                        MaxAge:   -1, 
                        HttpOnly: true,
                    })

                    http.Redirect(w, r, r.URL.String(), http.StatusFound)
                    return
                }
                var session map[string]string
                if err := json.Unmarshal([]byte(val), &session); err != nil {
                    responses.ServerError(w)
                    return
                }
                if session["Step"] != step{
                    http.Redirect(w, r, os.Getenv("AUTH_SERVER_DOMAIN")+"/"+session["Step"]+"?redirect_uri="+rawRedirectURI+"&scope="+scope+"&response_type="+response_type+"&client_id="+client_id+"&code_challenge_method="+code_challenge_method+"&code_challenge="+code_challenge+"&state="+state, http.StatusSeeOther)
                    return
                }
            }else{
                //duplicazione orrenda poi la spezzo in funzione riusabile
            var secure bool = true
            jti := uuid.New().String()
            iat := time.Now().UTC()
            exp := iat.Add(time.Minute*10)
            if os.Getenv("DEV_MODE")!=""{
                secure = false
            }
            var session SessionData 
            if nonce != ""{
                session.Nonce = nonce
            }
            session.ClientId = client_id
            session.RedirectURI = rawRedirectURI
            session.Scope = scope
            session.State = state
            session.ResponseType = response_type
            session.CodeChallengeMethod = code_challenge_method
            session.CodeChallenge = code_challenge
            session.Step = "login"
            sessionBytes, err := json.Marshal(session)
            if err != nil {
                responses.ServerError(w)
                return
            }
            errredis:=db.RDB.Set(ctx, jti, sessionBytes, exp.Sub(time.Now())).Err()
            if errredis!=nil{
                fmt.Printf("Error during setting setting session data on Redis:%v\n",errredis)
                responses.ServerError(w)
                return
            }
            claims := jwts.MapClaims{
                "iat": iat,
                "exp": exp.Unix(),
                "jti": jti,
            }
            token, errjwt := jwts.CreateToken(claims, nil)
            if errjwt != nil {
                    responses.ServerError(w)
            }
            authDomainRaw := os.Getenv("AUTH_SERVER_DOMAIN")
            parsedDomain, _ := url.Parse(authDomainRaw)
            cookieDomain := parsedDomain.Hostname()
            newcookie := &http.Cookie{
            Name:     "session_token",
            Value:    token,
            Path:     "/",
            Domain:   cookieDomain,
            MaxAge:   600, 
            HttpOnly: true, 
            Secure:   secure, 
            SameSite: http.SameSiteLaxMode,
            }
            http.SetCookie(w, newcookie)
            }
        }



        next(w,r)
        }
    }






func Protected(next http.HandlerFunc,  isRefresh bool) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        var rawToken string
        if isRefresh {
            cookie, err := r.Cookie("refresh_token")
            if err != nil {
                responses.Unauthorized(w, "missing_refresh_token", "Refresh token cookie is missing")
                return
            }
            rawToken = cookie.Value
        } else {
            authHeader := r.Header.Get("Authorization")
            if !strings.HasPrefix(authHeader, "DPoP ") {
                responses.Unauthorized(w, "missing_token", "DPoP authorization token is missing")
                return
            }
            rawToken = strings.TrimPrefix(authHeader, "DPoP ")
        }


        token, err := jwts.ValidateToken(rawToken)
        if err != nil || !token.Valid {
            if err != nil && strings.Contains(err.Error(), "expired") {
                responses.Unauthorized(w, "expired_token", "Token expired")
            } else {
                fmt.Printf("%v", err)
                responses.Unauthorized(w, "invalid_token", "Token is invalid")
            }
            return
        }

        claims, ok := token.Claims.(jwts.MapClaims)
        if !ok {
            responses.Unauthorized(w, "invalid_token", "Cannot parse token claims")
            return
        }
        if isRefresh {
            refreshClaim, _ := claims["refresh"].(bool)
            if !refreshClaim {
                responses.Unauthorized(w, "invalid_token_type", "Token is not a valid refresh token")
                return
            }
        }
        authDomain := os.Getenv("AUTH_SERVER_DOMAIN")
        isValidAudience := false

        switch v := claims["aud"].(type) {
        case string:
            if strings.Contains(v, authDomain) {
                isValidAudience = true
            }
        case []interface{}:
            for _, a := range v {
                if str, ok := a.(string); ok && strings.Contains(str, authDomain) {
                    isValidAudience = true
                    break
                }
            }
        }

        if !isValidAudience {
            fmt.Printf("Claims ricevuti: %v\n", claims)
            responses.BadRequest(w, "invalid_aud", "Invalid aud")
            return
        }

        accessJTI, _ := claims["jti"].(string)
        familyJTI, _ := claims["family"].(string)
        if accessJTI == "" {
            responses.Unauthorized(w, "invalid_token", "Missing jti in access token")
            return
        }
        if familyJTI == "" && isRefresh == false {
            responses.Unauthorized(w, "invalid_token", "Missing family in access token")
            return
        }
        if isRefresh{
            familyJTI = accessJTI
        }

        scheme := "https"
        if os.Getenv("DEV_MODE") != "" {
            scheme = "http"
        }
        expectedHTU := fmt.Sprintf("%s://%s%s", scheme, r.Host, r.URL.Path)

        dpopHeader := r.Header.Get("DPoP")
        if dpopHeader == "" {
            responses.BadRequest(w, "missing_DPoP", "DPoP header is missing")
            return
        }






        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()

        collection := db.MongoDB.Collection("tokens")

        var registeredToken bson.M
        err = collection.FindOne(ctx, bson.M{
            "family_jti": familyJTI,
        }).Decode(&registeredToken)
        if err != nil {
            responses.Unauthorized(w, "unauthorized_token", "Unauthorized token")
            return
        }


        if banned, _ := registeredToken["banned"].(bool); banned {
            responses.Unauthorized(w, "revoked_token", "Token has been revoked")
            return
        }
        var bannedDoc bson.M
        if blockedErr := collection.FindOne(ctx, bson.M{
            "banned": true,
            "$or": bson.A{
                bson.M{"family_jti": familyJTI},
            },
        }).Decode(&bannedDoc); blockedErr == nil {
            responses.Unauthorized(w, "revoked_token", "Token has been revoked")
            return
        }
        storedPubKeyRaw, ok := registeredToken["public_key"].(bson.M)
        if !ok {
            responses.Unauthorized(w, "invalid_dpop", "Invalid public key format")
            return
        }

        ecdsaPubKey, err := cryptokeys.JWKToECDSAPublicKey(storedPubKeyRaw)
        if err != nil {
            responses.Unauthorized(w, "invalid_dpop", "Invalid public key")
            return
        }

        dpopClaims, err := jwts.ValidateDPoPWithKnownKey(
            dpopHeader,
            r.Method,
            expectedHTU,
            ecdsaPubKey,
        )

        tokenID := registeredToken["_id"].(primitive.ObjectID)
        if err != nil {
            responses.Unauthorized(w, "invalid_dpop", "DPoP verification failed")
            _, _ = collection.UpdateOne(ctx,
                bson.M{"_id": tokenID},
                bson.M{"$set": bson.M{"banned": true}},
            )
            return
        }

        dpopJTI, _ := dpopClaims["jti"].(string)
        if dpopJTI == "" {
            responses.BadRequest(w, "invalid_dpop", "Missing jti in DPoP token")
            return
        }




        dpopJTIs, _ := registeredToken["DPoP_jtis"].(primitive.A)
        for _, v := range dpopJTIs {
            if existing, ok := v.(string); ok && existing == dpopJTI {
                _, _ = collection.UpdateOne(ctx,
                    bson.M{"_id": tokenID},
                    bson.M{"$set": bson.M{"banned": true}},
                )
                responses.Unauthorized(w, "replay_attack_detected", "Replay attack detected")
                return
            }
        }
        if _, err = collection.UpdateOne(ctx,
            bson.M{"_id": tokenID},
            bson.M{"$push": bson.M{"DPoP_jtis": dpopJTI}},
        ); err != nil {
            responses.ServerError(w)
            return
        }

        grantType, _ := claims["grant_type"].(string)
        if grantType == "authorization_code" {
            fpHash, _ := utils.GenerateFingerprint(r)
            storedFP, _ := registeredToken["fingerprint"].(string)
            if storedFP != fpHash {
                _, _ = collection.UpdateOne(ctx,
                    bson.M{"_id": tokenID},
                    bson.M{"$set": bson.M{"banned": true}},
                )
                responses.Unauthorized(w, "unknown_device", "Unknown device")
                return
            }
        }



        

        next(w, r)
    }
}