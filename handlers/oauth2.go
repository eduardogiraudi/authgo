package handlers
import(
 "github.com/golang-jwt/jwt/v5"
    "encoding/base64"
	"encoding/json"
	"auth/db"             
	"context"
	"time"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"       
	"auth/passwords"
	"auth/utils"
	"fmt"
	"errors"
	"github.com/google/uuid"
	"net/http"
	"auth/responses"
	"auth/jwts"
	"os"
	"strings"           
)
func Token(w http.ResponseWriter, r *http.Request) {
    var req TokenRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        responses.BadRequest(w, "invalid_json", "Invalid JSON")
        return
    }
    var savedInfo map[string]interface{}
    grant_type := req.GrantType
    client_id := req.ClientID
    client_secret := req.ClientSecret

    authHeader := r.Header.Get("Authorization")
    if authHeader != "" && strings.HasPrefix(authHeader, "Basic ") {
        payload := strings.TrimPrefix(authHeader, "Basic ")
        decodedBytes, err := base64.StdEncoding.DecodeString(payload)
        if err == nil {
            parts := strings.SplitN(string(decodedBytes), ":", 2)
            if len(parts) == 2 {
                client_id = parts[0]
                client_secret = parts[1]
            }
        }
    }

    dpopHeader := r.Header.Get("DPoP")
    if dpopHeader == "" {
        responses.BadRequest(w, "missing_DPoP", "DPoP header is missing")
        return
    }

    currentURL := fmt.Sprintf("%s%s", os.Getenv("AUTH_SERVER_DOMAIN"), r.URL.Path)
    claims, jwkdpop,err := jwts.ValidateFirstTimeDPoP(dpopHeader, "POST", currentURL)
    _ = claims
    if err != nil {
        if errors.Is(err, jwt.ErrTokenExpired) {
            responses.Unauthorized(w, "expired_dpop", "DPoP token expired")
        } else {
            responses.Unauthorized(w, "invalid_dpop", "Invalid DPoP token or claims")
        }
        return
    }

    if grant_type != "authorization_code" && grant_type != "client_credentials" {
        responses.BadRequest(w, "unsupported_grant_type", "Unsupported grant type")
        return
    }

    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    var client bson.M
    collection := db.MongoDB.Collection("clients")

    if grant_type == "client_credentials" {
        if client_id == "" {
            responses.BadRequest(w, "invalid_request", "Missing client_id")
            return
        }

        errcli := collection.FindOne(ctx, bson.M{"client_id": client_id}).Decode(&client)
        if errcli != nil {
            responses.BadRequest(w, "invalid_client", "Client not found")
            return
        }

        isValid, err := passwords.ComparePassword(client_secret, client["client_secret"].(string))
        if err != nil || !isValid {
            responses.BadRequest(w, "invalid_client", "Invalid client secret")
            return
        }

    } else if grant_type == "authorization_code" {
        authorizationCode := req.Code
        redirectURI := req.RedirectURI

        if authorizationCode == "" || redirectURI == "" {
            responses.BadRequest(w, "invalid_request", "Missing code or redirect_uri")
            return
        }

        savedInfoRaw, err := db.RDB.Get(ctx, authorizationCode).Result()
        if err != nil {
            responses.BadRequest(w, "invalid_grant", "Invalid or expired authorization code")
            return
        }

        
        if err := json.Unmarshal([]byte(savedInfoRaw), &savedInfo); err != nil {
            responses.ServerError(w)
            return
        }

        if savedInfo["ClientId"].(string) != client_id {
            responses.BadRequest(w, "invalid_client", "Client mismatch")
            return
        }

        errcli := collection.FindOne(ctx, bson.M{"client_id": client_id}).Decode(&client)
        if errcli != nil {
            responses.BadRequest(w, "invalid_client", "Client not found")
            return
        }

        authorizedURIs, _ := client["authorized_redirects"].(primitive.A)
        uriValid := false
        for _, uri := range authorizedURIs {
            u := strings.TrimSuffix(uri.(string), "/")
            r := strings.TrimSuffix(redirectURI, "/")

            if u == r {
                uriValid = true
                break
            }
        }
        if !uriValid {
            responses.BadRequest(w, "invalid_grant", "Redirect URI mismatch")
            return
        }

        codeChallenge, hasPKCE := savedInfo["CodeChallenge"].(string)
        if hasPKCE && codeChallenge != "" {
            codeVerifier := req.CodeVerifier
            if codeVerifier == "" {
                responses.BadRequest(w, "invalid_request", "Missing code_verifier")
                return
            }
            if !utils.VerifyCodeVerifier(codeVerifier, codeChallenge) {
                responses.BadRequest(w, "invalid_grant", "Invalid code_verifier")
                return
            }
        } else {
            isValid, err := passwords.ComparePassword(client_secret, client["client_secret"].(string))
            if err != nil || !isValid {
                responses.BadRequest(w, "invalid_client", "Invalid client secret")
                return
            }
        }

        db.RDB.Del(ctx, authorizationCode)
    }
    id_tok_h:= map[string]any{
        "typ":"id_token+JWT",
    }
    rt_tok_h:= map[string]any{
        "typ":"rt+JWT",
    }
    at_tok_h:= map[string]any{
        "typ":"at+JWT",
    }
    if grant_type == "authorization_code"{
        device_id := uuid.New().String()
        id_tok_jti:=uuid.New().String()
        a_tok_jti:=uuid.New().String()
        r_tok_jti:=uuid.New().String()
        iat:=time.Now().UTC()
         payload:= jwts.MapClaims{
            "aud": client_id, 
            "iat" : iat.Unix(),
            "exp" : iat.Add(time.Minute*10).Unix(),
            "iss": os.Getenv("AUTH_SERVER_DOMAIN"),
            "sub":savedInfo["UserID"],
            "auth_time": time.Now().UTC().Unix(),
            "device_id": device_id,
            "grant_type": "authorization_code",
            "client_id": client_id,
            "family": r_tok_jti,


        }
        if nonce, ok := savedInfo["nonce"].(string); ok && nonce != "" {
        payload["nonce"] = nonce
    }

    payload["jti"] = id_tok_jti
    id_tok, _ := jwts.CreateToken(payload, id_tok_h)
    delete(payload, "nonce")
        payload["jti"]=a_tok_jti
        payload["aud"] = []string{os.Getenv("AUTH_SERVER_DOMAIN"),os.Getenv("RESOURCE_SERVER_DOMAIN")}
        a_tok,_ := jwts.CreateToken(payload, at_tok_h)
        payload["jti"]=r_tok_jti
        payload["refresh"] = true
        payload["exp"] = iat.Add(time.Hour*24*10).Unix()
        payload["aud"] = os.Getenv("AUTH_SERVER_DOMAIN") + "/refresh_token"

        r_tok, _ := jwts.CreateToken(payload, rt_tok_h)
        var secure bool = true
        if os.Getenv("DEV_MODE")!=""{
                        secure = false
                    }
        http.SetCookie(w, &http.Cookie{
            Name:     "refresh_token",
            Value:    r_tok,
            Path:     "/refresh_token",       
            Domain:   "",              
            Expires:  iat.Add(time.Hour * 24 * 10),
            HttpOnly: true,             
            Secure:   secure,             
            SameSite: http.SameSiteStrictMode, 
        })
        responses.OK(w,map[string]any{
            "access_token": a_tok,
            "id_token": id_tok,
            "token_type": "DPoP",
            "expires_in": 600,
            })
        collection = db.MongoDB.Collection("tokens")
        finger, device_info:=utils.GenerateFingerprint(r)
        dpopKeyData := bson.M{
            "kty": "EC",
            "crv": jwkdpop.Curve.Params().Name,
            "x": base64.RawURLEncoding.EncodeToString(jwkdpop.X.Bytes()),
            "y": base64.RawURLEncoding.EncodeToString(jwkdpop.Y.Bytes()),
        }
        newtok := bson.M{
        "family_jti": r_tok_jti,
        "public_key": dpopKeyData,
        "user_id": savedInfo["UserID"],
        "client_id": client_id,
        "scope": savedInfo["Scope"],
        "grant_type": "authorization_code",
        "fingerprint": finger,
        "device_info": device_info,
        "device_id": device_id,
        "banned": false,
        "DPoP_jtis": []string{claims["jti"].(string)},
        }

    _, err = collection.InsertOne(ctx, newtok)
    if err != nil {
        fmt.Printf("Error during inserting seed user: %v\n", err)
        return
    }
        return
    }
    if grant_type == "client_credentials" {
        device_id := uuid.New().String()
        family_jti := uuid.New().String()
        a_tok_jti := uuid.New().String()
        iat := time.Now().UTC()

        payload := jwts.MapClaims{
            "jti":        a_tok_jti,
            "iss":        os.Getenv("AUTH_SERVER_DOMAIN"),
            "sub":        client["_id"].(primitive.ObjectID).Hex(),
            "aud":        []string{os.Getenv("AUTH_SERVER_DOMAIN"), os.Getenv("RESOURCE_SERVER_DOMAIN")},
            "iat":        iat.Unix(),
            "exp":        iat.Add(time.Hour * 1).Unix(), 
            "grant_type": "client_credentials",
            "client_id":  client_id,
            "device_id":  device_id,
        }

        token, err := jwts.CreateToken(payload, at_tok_h)
        if err != nil {
            responses.ServerError(w)
            return
        }

        dpopKeyData := bson.M{
            "kty": "EC",
            "crv": jwkdpop.Curve.Params().Name,
            "x": base64.RawURLEncoding.EncodeToString(jwkdpop.X.Bytes()),
            "y": base64.RawURLEncoding.EncodeToString(jwkdpop.Y.Bytes()),
        }

        collection = db.MongoDB.Collection("tokens")
        newtok := bson.M{
            "family_jti": family_jti,
            "public_key": dpopKeyData,
            "user_id":    client["_id"].(primitive.ObjectID).Hex(),
            "client_id":  client_id,
            "grant_type": "client_credentials",
            "device_id":  device_id,
            "DPoP_jtis":  []string{claims["jti"].(string)},
            "banned":     false,
        }

        _, err = collection.InsertOne(ctx, newtok)
        if err != nil {
            responses.ServerError(w)
            return
        }

        responses.OK(w, map[string]any{
            "access_token": token,
            "token_type":   "DPoP",
            "expires_in":   3600,
        })
        return
    }

    fmt.Println("Tutto validato! Procedo alla generazione...")
}
func Authorize(w http.ResponseWriter, r *http.Request) {
    cookie, errtok := r.Cookie("session_token")
    var req AuthorizeRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        responses.BadRequest(w, "invalid_json","Invalid JSON")
        return
    }
    if errtok != nil {
        responses.BadRequest(w, "expired_session", "Expired session. Please refresh your browser")
        return
    }
    if req.Confirmation == false {
        responses.BadRequest(w,"missing_confirmation", "Missing confirmation")
        return
    }
    authorization_code:=utils.AuthorizationCodeGenerator()
    if authorization_code == ""{
        responses.ServerError(w)
        return
    }
    token, validatetokerr := jwts.ValidateToken(cookie.Value)
    if validatetokerr == nil && token.Valid {

        claims := token.Claims.(jwts.MapClaims)

        jti := claims["jti"].(string)
        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()
        val, err := db.RDB.Get(ctx, jti).Result()
        errdel := db.RDB.Del(ctx, jti).Err()
        if err != nil || errdel != nil{
            responses.BadRequest(w, "expired_session", "Expired session. Please refresh your browser")
            return
        }
        var data map[string]interface{}
        json.Unmarshal([]byte(val), &data)
        if err := json.Unmarshal([]byte(val), &data); err != nil {
        responses.ServerError(w)
        return
        }
        data["AuthorizationCode"] = authorization_code
        jsonData, errMarshal := json.Marshal(data)
        if errMarshal != nil {
            responses.ServerError(w)
            return
        }
        errSet := db.RDB.Set(ctx, authorization_code, jsonData, 5*time.Minute).Err()
        if errSet != nil {
            responses.ServerError(w)
            return
        }
        var secure bool = true
        if os.Getenv("DEV_MODE")!=""{
                        secure = false
                    }
        http.SetCookie(w, &http.Cookie{
            Name:     "session_token",
            Value:    "",
            Path:     "/", 
            MaxAge:   -1,
            HttpOnly: true,
            Secure:   secure, 
            SameSite: http.SameSiteLaxMode,
        })
        responses.OK(w,map[string]any{
            "code":    authorization_code,
            })
    }else{
        responses.BadRequest(w, "expired_session", "Expired session. Please refresh your browser")
        return

    }
}
func Revoke(w http.ResponseWriter, r *http.Request) {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
        collection := db.MongoDB.Collection("tokens")

    var req RevokeRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        responses.BadRequest(w, "invalid_json", "Invalid JSON body")
        return
    }
    claims, err := jwts.ValidateTokenIgnoreClaims(req.Token)
    if err != nil {
        responses.BadRequest(w, "invalid_token", "Invalid token")
        return
    }
    
    sub, okSub := claims["sub"].(string)
    fam, okFam := claims["family"].(string)

    if !okSub || !okFam {
        responses.BadRequest(w, "invalid_token_claims", "Invalid token claims")
        return
    }
    ownerclaims, nojwtheader := jwts.GetClaims(r)
    if nojwtheader == nil && ownerclaims["sub"] != sub{
        _, _ = collection.UpdateMany(ctx,
            bson.M{
            "user_id":    sub, 
        },
            bson.M{"$set": bson.M{
                "banned":     true,
            }},
        )
         _, _ = collection.UpdateMany(ctx,
            bson.M{
            "user_id":    ownerclaims["sub"], 
        },
            bson.M{"$set": bson.M{
                "banned":     true,
            }},
        )
        http.SetCookie(w, &http.Cookie{
        Name:     "refresh_token",
        Value:    "",
        Path:     "/refresh_token", 
        MaxAge:   -1,
        HttpOnly: true,
        Secure:   true, 
        SameSite: http.SameSiteStrictMode,
    })
        responses.Unauthorized(w, "token_theft_detected", "Token theft detected")
        return
    }

    filter := bson.M{
        "user_id":    sub,
        "family_jti": fam,
    }

    _, err = collection.UpdateOne(ctx,
        filter,
        bson.M{"$set": bson.M{
            "banned":     true,
        }},
    )

    if err != nil {
        responses.ServerError(w)
        return
    }

    http.SetCookie(w, &http.Cookie{
        Name:     "refresh_token",
        Value:    "",
        Path:     "/refresh_token", 
        MaxAge:   -1,
        HttpOnly: true,
        Secure:   true, 
        SameSite: http.SameSiteStrictMode,
    })

    responses.OK(w, "Token revoked and session terminated")
}
func Refresh(w http.ResponseWriter, r *http.Request){
    cookie, _ := r.Cookie("refresh_token")

    rawToken := cookie.Value
    token, _ := jwts.ValidateToken(rawToken)
    claims, _ := token.Claims.(jwts.MapClaims)
    id_tok_h:= map[string]any{
        "typ":"id_token+JWT",
    }

    at_tok_h:= map[string]any{
        "typ":"at+JWT",
    }
        id_tok_jti:=uuid.New().String()
        a_tok_jti:=uuid.New().String()
        iat:=time.Now().UTC()
         payload:= jwts.MapClaims{
            "aud": []string{os.Getenv("AUTH_SERVER_DOMAIN"),os.Getenv("RESOURCE_SERVER_DOMAIN")}, 
            "iat" : iat.Unix(),
            "exp" : iat.Add(time.Minute*10).Unix(),
            "iss": os.Getenv("AUTH_SERVER_DOMAIN"),
            "sub":claims["sub"].(string),
            "auth_time": claims["auth_time"],
            "device_id": claims["device_id"].(string),
            "grant_type": "authorization_code",
            "client_id": claims["client_id"].(string),
            "family": claims["jti"].(string),
            "jti": id_tok_jti,


        }
            id_tok, _ := jwts.CreateToken(payload, id_tok_h)
            payload["jti"] = a_tok_jti
            at_tok, _:= jwts.CreateToken(payload, at_tok_h)
    responses.OK(w, map[string]any{"access_token":at_tok,"token_type": "DPoP","id_token": id_tok,

                "expires_in": 600})
}
func Userinfo(w http.ResponseWriter, r *http.Request) {
    claims, _ := jwts.GetClaims(r)
    sub := claims["sub"]
    fam := claims["family"]

    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    tokensCollection := db.MongoDB.Collection("tokens")
    usersCollection := db.MongoDB.Collection("users")

    filter := bson.M{
        "user_id":    sub,
        "family_jti": fam,
    }

    var session bson.M
    err := tokensCollection.FindOne(ctx, filter).Decode(&session)
    if err != nil {
        responses.ServerError(w) 
        return
    }

    if session["grant_type"] == "client_credentials" {
        responses.OK(w, map[string]interface{}{
            "sub": session["user_id"],
        })
        return
    }

    scopeString, _ := session["scope"].(string)
    scopes := strings.Split(scopeString, " ")

    userID, _ := primitive.ObjectIDFromHex(session["user_id"].(string))
    
    var user bson.M
    err = usersCollection.FindOne(ctx, bson.M{"_id": userID}).Decode(&user)
    if err != nil {
        responses.ServerError(w)
        return
    }

    resp := make(map[string]interface{})

    for _, s := range scopes {
        switch s {
        case "openid":
            resp["sub"] = session["user_id"]

        case "email":
            email, _ := user["email"].(string)
            if email == "" {
                email, _ = user["username"].(string)
            }
            resp["email"] = email
            
            verified, _ := user["email_verified"].(bool)
            resp["email_verified"] = verified

        case "profile":
            resp["nickname"] = user["username"]
        }
    }

    responses.OK(w, resp)
}