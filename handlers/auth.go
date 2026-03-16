package handlers

import (
 "encoding/json"
        "auth/db"
        "auth/cryptokeys"
"math/rand"
        "context"
        "time"
    "go.mongodb.org/mongo-driver/bson"
        "go.mongodb.org/mongo-driver/bson/primitive"

    "github.com/altcha-org/altcha-lib-go"
    "auth/passwords"
    "auth/utils"
    "fmt"
    "errors"
                "github.com/google/uuid"
                emailverifier "github.com/AfterShip/email-verifier"
              		"go.mongodb.org/mongo-driver/mongo"
                  "net/http"
                  "auth/responses"
                  "auth/jwts"
                  "os"
                  "path/filepath"
                  "strings"
                  
)
var verifier = emailverifier.NewVerifier().EnableSMTPCheck()


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

func Register(w http.ResponseWriter, r *http.Request){
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
    defer cancel()
    
    var req RegisterRequest
    secret := os.Getenv("ALTCHA_HMAC_KEY")

    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		responses.BadRequest(w, "invalid_json", "Invalid JSON")
		return
	}
 ok, errcaptcha := altcha.VerifySolution(req.CaptchaValue, secret, true)
    if errcaptcha != nil || !ok {
        responses.Unauthorized(w, "invalid_altcha", "Invalid Altcha value or expired")
        return
    }
	result, err := verifier.Verify(req.Email)
	if err != nil {
		responses.ServerError(w)
		return
	}
	if !result.Syntax.Valid {
		responses.BadRequest(w, "invalid_email_format", "Invalid email format")
		return
	}


	if result.Reachable == "no" {
		responses.BadRequest(w, "invalid_email", "Unreachable email")
		return
	}

	if result.Disposable {
		responses.Forbidden(w, "Temporary emails are not allowed")
		return
	}
	if utils.PasswordValidator(req.Password) == false {
		responses.BadRequest(w, "invalid_password", "Password must be between 12 and 36 characters long, contain at least one lowercase letter, one uppercase letter, one number, and one special character.")
		return
	}
	collection := db.MongoDB.Collection("users")
	var user bson.M
    err = collection.FindOne(ctx, bson.M{"$or": []interface{}{bson.M{"username": req.Username}, bson.M{"email": req.Email},},}).Decode(&user)
    if err == nil {
            responses.BadRequest(w, "user_already_exists", "Username or email already in use")
            return
        }
    
        if !errors.Is(err, mongo.ErrNoDocuments) {
            responses.ServerError(w)
            return
        }
        password, errpass := passwords.GenerateHash(req.Password)
        if errpass!=nil{
        responses.ServerError(w)
        return
        }
    
    user = bson.M{
            "username": req.Username,
            "email": req.Email,
            "password": password,
        }
    _,err=collection.InsertOne(ctx,user)
    if err != nil {
    responses.ServerError(w)
    return 
    }
    
    responses.OK(w, "ok")
    return
    
}
func Logout(w http.ResponseWriter, r *http.Request){
    ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
    defer cancel()
    claims, _ := jwts.GetClaims(r)
    sub := claims["sub"]
    fam := claims["family"]

    collection := db.MongoDB.Collection("tokens")

    filter := bson.M{
        "user_id":    sub,
        "family_jti": fam,
    }
    _, _ = collection.UpdateOne(ctx,
        filter,
        bson.M{"$set": bson.M{"banned": true}},
    )
    http.SetCookie(w, &http.Cookie{
                        Name:     "refresh_token",
                        Value:    "",
                        Path:     "/refresh_token",
                        Domain:   "",
                        MaxAge:   -1, 
                        HttpOnly: true,
    })
    responses.OK(w,"Token revoked successfully")
    return
}




func ChangePasswordWithToken(w http.ResponseWriter, r *http.Request){
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
    defer cancel()
    var req ChangePasswordWithTokenRequest
    
secret := os.Getenv("ALTCHA_HMAC_KEY")
if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		responses.BadRequest(w, "invalid_json", "Invalid JSON")
		return
	}
 ok, errcaptcha := altcha.VerifySolution(req.CaptchaValue, secret, true)
    if errcaptcha != nil || !ok {
        responses.Unauthorized(w, "invalid_altcha", "Invalid Altcha value or expired")
        return
    }
    valid:=utils.PasswordValidator(req.NewPassword)
    if valid == false {
    responses.BadRequest(w, "invalid_password", "Password must be between 12 and 36 characters long, contain at least one lowercase letter, one uppercase letter, one number, and one special character.")
    return
    }
	collection := db.MongoDB.Collection("users")
	claims, _ := jwts.GetClaims(r)
	sub := claims["sub"].(string)
	cid := claims["client_id"].(string)
	if cid != os.Getenv("APP_CLIENT_ID"){
		responses.Forbidden(w, "Insufficient permissions to change password. Use the official application")
		return
	}
    var user bson.M
    oid, err := primitive.ObjectIDFromHex(sub)
        if err != nil {
            responses.ServerError(w)
            return 
        }
errusrnotfound := collection.FindOne(ctx, bson.M{
	"_id": oid,
}).Decode(&user)
if errusrnotfound != nil {
        responses.NotFound(w, "user_not_found", "User not found")
        return
    }
    valid, error := passwords.ComparePassword(req.Password, user["password"].(string))
    if error != nil {
    responses.ServerError(w)
    return
    }
    if valid == false {
        responses.BadRequest(w,"invalid_credentials", "Invalid credentials")
        return
    }
    pwd,errhash:=passwords.GenerateHash(req.NewPassword)
    if errhash != nil{
    responses.ServerError(w)
    return
    }
    _,errupd:=collection.UpdateOne(ctx, bson.M{
	"_id": oid,
    },bson.M{"$set": bson.M{"password": pwd}})
    if errupd != nil {
    responses.ServerError(w)
   	return 
    }
	responses.OK(w,"ok")
	return
}



func UpdateSessionStep(ctx context.Context, jti string, step string, userID string) error {
    val, err := db.RDB.Get(ctx, jti).Result()
    if err != nil {
        return err
    }

    var sessionData map[string]interface{}
    if err := json.Unmarshal([]byte(val), &sessionData); err != nil {
        return err
    }

    sessionData["Step"] = step
    sessionData["UserID"] = userID

    updatedValue, err := json.Marshal(sessionData)
    if err != nil {
        return err
    }

    return db.RDB.Set(ctx, jti, updatedValue, 10*time.Minute).Err()
}

func Otp(w http.ResponseWriter, r *http.Request){
    var req OTPRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        responses.BadRequest(w, "invalid_json","Invalid JSON")
        return
    }
    cookie, errtok := r.Cookie("session_token")
        if errtok != nil {
        responses.BadRequest(w, "expired_session", "Expired session. Please refresh your browser")
        return
    }
    token, validatetokerr := jwts.ValidateToken(cookie.Value)
    if validatetokerr == nil && token.Valid{
        claims := token.Claims.(jwts.MapClaims)
        jti := claims["jti"].(string)
        ctx, cancel := context.WithTimeout(r.Context(), 35*time.Second)
        defer cancel()
        val, err := db.RDB.Get(ctx, jti).Result()
        if err != nil {
            responses.BadRequest(w, "expired_session", "Expired session. Please refresh your browser")
            return
        }
        var data map[string]interface{}
        json.Unmarshal([]byte(val), &data)
        queue_id := uuid.New().String()
        user_id := data["UserID"].(string)
        finger, _:=utils.GenerateFingerprint(r)
        var verify VerifyOTP
        verify.UserID = user_id
        verify.Fingerprint = finger
        verify.QueueID = queue_id
        verify.OTP = req.OTP
        verifyJSON, _ := json.Marshal(verify)
        errpush := db.RDB.RPush(ctx, "verify_otp", verifyJSON).Err()
        if errpush != nil {
            responses.ServerError(w)
            return
        }
        responseKey := fmt.Sprintf("%s/%s:%s", queue_id, user_id, finger)
        result, err := db.RDB.BLPop(ctx, 30*time.Second, responseKey).Result()
        if err != nil {
            responses.ServerError(w)
            return
        }
        var workerRes map[string]interface{}
        if err := json.Unmarshal([]byte(result[1]), &workerRes); err != nil {
            responses.ServerError(w)
            return
        }
        isValid, _ := workerRes["valid"].(bool)

        if isValid {
            errUpdate := UpdateSessionStep(ctx, jti, "authorize", user_id)
            if errUpdate != nil {
                responses.ServerError(w)
                return
            }    
            responses.OK(w, "authorize")
        } else {
            reason, _ := workerRes["reason"].(string)
            if reason == "too_many_attempts" {
                errdel := db.RDB.Del(ctx, jti).Err()
                if err != nil || errdel != nil{
                    responses.BadRequest(w, "expired_session", "Expired session. Please refresh your browser")
                    return
                }
                responses.BadRequest(w, "too_many_attempts", "Too many attempts")
            } else if reason == "expired_otp"{
                responses.BadRequest(w, "expired_otp", "OTP expired. Please login again.")
                return

            }else {
                remaining, _ := workerRes["remaining_attempts"]
                responses.BadRequest(w, "invalid_otp", fmt.Sprintf("Invalid OTP, %v attempts remaining ", remaining))
            }
        }



    }else{
        responses.BadRequest(w, "expired_session", "Expired session. Please refresh your browser")
        return
        }

}






func ScopeDetails(w http.ResponseWriter, r *http.Request) {
    cookie, errtok := r.Cookie("session_token")
    if errtok != nil {
        responses.BadRequest(w, "expired_session", "Expired session. Please refresh your browser")
        return
    }

    token, validatetokerr := jwts.ValidateToken(cookie.Value)
    if validatetokerr == nil && token.Valid {
        claims := token.Claims.(jwts.MapClaims)
        jti := claims["jti"].(string)
        ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
        defer cancel()

        val, err := db.RDB.Get(ctx, jti).Result()
        if err != nil {
            responses.BadRequest(w, "expired_session", "Expired session. Please refresh your browser")
            return
        }

        var data map[string]interface{}
        json.Unmarshal([]byte(val), &data)

        scopeRaw, ok := data["Scope"].(string)
        if !ok {
            responses.BadRequest(w, "invalid_scope", "No scope found in session")
            return
        }

        scopeDescriptions := map[string]string{
            "openid":  "Allows the application to authenticate the user.",
            "profile": "Access to the user's basic profile information.",
            "email":   "Access to the user's email address.",
            "address": "Access to the user's physical address.",
            "phone":   "Access to the user's phone number.",
        }

        scopes := strings.Split(scopeRaw, " ")
        var descriptions []string

        for _, s := range scopes {
            if desc, exists := scopeDescriptions[s]; exists {
                descriptions = append(descriptions, desc)
            }
        }

        responses.OK(w, descriptions)

    } else {
        responses.BadRequest(w, "invalid_token", "Invalid token")
        return
    }
}


func Login(w http.ResponseWriter, r *http.Request) {
    var req LoginRequest
    cookie, errtok := r.Cookie("session_token")
    if errtok != nil {
        responses.BadRequest(w, "expired_session", "Expired session. Please refresh your browser")
        return
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        responses.BadRequest(w, "invalid_json","Invalid JSON")
        return
    }
    secret := os.Getenv("ALTCHA_HMAC_KEY")
    
    ok, err := altcha.VerifySolution(req.CaptchaValue, secret, true)
    if err != nil || !ok {
        responses.Unauthorized(w, "invalid_altcha", "Invalid Altcha value or expired")
        return
    }
    var user bson.M
    collection := db.MongoDB.Collection("users")
    ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
    defer cancel()
    filter := bson.M{
        "$or": []bson.M{
            {"username": req.Username},
            {"email": req.Username},
        },
    }
    errusrnotfound := collection.FindOne(ctx, filter).Decode(&user)
    if errusrnotfound != nil {
    	responses.BadRequest(w,"invalid_credentials", "Invalid credentials")
        return
    }
    valid, error := passwords.ComparePassword(req.Password, user["password"].(string))
    if error!=nil{
        responses.ServerError(w)
        return
    }
    if valid == false {
        responses.BadRequest(w,"invalid_credentials", "Invalid credentials")
        return
    }
    idRaw := user["_id"]
    oid, ok := idRaw.(primitive.ObjectID)
    if !ok {
        responses.ServerError(w)
        return
    }
    userID := oid.Hex()
    
    emittedtokcollection := db.MongoDB.Collection("tokens")
    var hasTokens bson.M

    token, validatetokerr := jwts.ValidateToken(cookie.Value)

    
    DoesntHaveTokens := emittedtokcollection.FindOne(ctx, bson.M{
        "user_id": userID,
    }).Decode(&hasTokens)
if DoesntHaveTokens == nil {
    finger, _ := utils.GenerateFingerprint(r)
    
    if validatetokerr == nil && token.Valid {
        claims := token.Claims.(jwts.MapClaims)
        jti := claims["jti"].(string)

        val, err := db.RDB.Get(ctx, jti).Result()
        var sessionData map[string]interface{}
        if err == nil {
            json.Unmarshal([]byte(val), &sessionData)
        } else {
            sessionData = make(map[string]interface{})
        }

        sessionData["UserID"] = userID
        sessionData["Fingerprint"] = finger
        sessionData["Step"] = "login" 
        sessionBytes, _ := json.Marshal(sessionData)

        errSet := db.RDB.Set(ctx, jti, sessionBytes, 10*time.Minute).Err()
        if errSet != nil {
            responses.ServerError(w)
            return
        }

        errredis := db.RDB.RPush(ctx, "generate_otp", sessionBytes).Err()
        if errredis != nil {
            responses.ServerError(w)
            return
        }
    }

    responses.OK(w, "otp")
    return
}

    if validatetokerr == nil && token.Valid {
                claims := token.Claims.(jwts.MapClaims)
                jti := claims["jti"].(string)
                val, err := db.RDB.Get(ctx, jti).Result()
                errdel := db.RDB.Del(ctx, jti).Err()
                if err != nil || errdel!=nil {
                    responses.BadRequest(w, "expired_session", "Expired session. Please refresh your browser")
                    return
                }
                var sessionData map[string]interface{}
                json.Unmarshal([]byte(val), &sessionData)
                sessionData["Step"] = "authorize"
                sessionData["UserID"] = userID
                
                updatedValue, _ := json.Marshal(sessionData)

                errSet := db.RDB.Set(ctx, jti, updatedValue, 10*time.Minute).Err()
                if errSet != nil {
                    responses.ServerError(w)
                    return
                }

                responses.OK(w, "authorize")
                return
            }else{
                    responses.BadRequest(w, "expired_session", "Expired session. Please refresh your browser")
                    return


            }
}






func ServeStatic(w http.ResponseWriter, r *http.Request) {
    const staticDir = "./static/client/dist"

    requestedPath := strings.TrimPrefix(r.URL.Path, "/")
    requestedPath = filepath.Clean(requestedPath)

    fullPath := filepath.Join(staticDir, requestedPath)

    absStaticDir, err := filepath.EvalSymlinks(staticDir)
    if err != nil {
        responses.ServerError(w)
        return
    }

    absFullPath, err := filepath.EvalSymlinks(fullPath)
    if err != nil {
        http.ServeFile(w, r, filepath.Join(staticDir, "index.html"))
        return
    }

    if !strings.HasPrefix(absFullPath, absStaticDir+string(os.PathSeparator)) &&
        absFullPath != absStaticDir {
        responses.Forbidden(w, "forbidden")
        return
    }

    info, err := os.Stat(absFullPath)
    if err != nil || info.IsDir() {
        http.ServeFile(w, r, filepath.Join(staticDir, "index.html"))
        return
    }

    http.ServeFile(w, r, absFullPath)
}



func ForgotPassword(w http.ResponseWriter, r *http.Request){
 var req ForgotPasswordRequest
 queue_id := uuid.New().String()
   	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
    defer cancel()
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        responses.BadRequest(w, "invalid_json","Invalid JSON")
        return
    }
    secret := os.Getenv("ALTCHA_HMAC_KEY")
    ok, errcaptcha := altcha.VerifySolution(req.CaptchaValue, secret, true)
    if errcaptcha != nil || !ok {
        responses.Unauthorized(w, "invalid_altcha", "Invalid Altcha value or expired")
        return
    }
	collection := db.MongoDB.Collection("users")
	var user bson.M
       err := collection.FindOne(ctx, bson.M{"email": req.Email}).Decode(&user) 
       if err != nil {
           if errors.Is(err, mongo.ErrNoDocuments) {
           //enum attack prevention logic
           redisKey := "rate_limit:forgot_password:" + req.Email
           db.RDB.SetEx(ctx, "fake_queue:"+queue_id, "1", 30*time.Minute)
               
               
               count, _ := db.RDB.Incr(ctx, redisKey).Result()
               // timing attack prevention
               time.Sleep(time.Duration(100+rand.Intn(100)) * time.Millisecond)
               if count == 1 {
                   db.RDB.Expire(ctx, redisKey, 30*time.Minute)
               }
           
               if count > 3 {
                   responses.BadRequest(w, "rate_limit", "Too many attempts. Try again later.")
                   return
               }
           
               
           
               responses.OK(w, queue_id)
               return
           }
           responses.ServerError(w)
                   return
           }
           
           
           
           now := time.Now()
               
               recoveryData, exists := user["password_recovery"].(primitive.M)
               
               var count int = 0
               var lastAttempt time.Time
           
               if exists {
                   count = int(recoveryData["count"].(int32))
                   lastAttempt = recoveryData["last_attempt"].(primitive.DateTime).Time()
               }
           
               if count >= 3 {
                   if now.Sub(lastAttempt) < 30*time.Minute {
                       responses.BadRequest(w, "rate_limit", "Too many attempts. Try again later.")
                       return
                   }
                   count = 1
               } else {
                   count++
               }
               
               update := bson.M{
                   "$set": bson.M{
                       "requestedpasswordrecovery": true,
                       "password_recovery": bson.M{
                       "queue_id": queue_id,
                           
                           "count":        count,
                           "last_attempt": now,
                       },
                   },
               }
           
               _, err = collection.UpdateOne(ctx, bson.M{"email": req.Email}, update)
               if err != nil {
                   responses.ServerError(w)
                   return
               }
               
               var push RecoveryOtp
       
               push.QueueID = queue_id
               push.Email = req.Email
               pushJSON, _ := json.Marshal(push)
               //different type of otp since we need a longer one
               errredis := db.RDB.RPush(ctx, "generate_recovery_otp", pushJSON).Err()
               if errredis != nil {
                   responses.ServerError(w)
                   return
               }
	responses.OK(w, queue_id)
    return
	
}

func ChangePasswordWithOTP(w http.ResponseWriter, r *http.Request){
	var req ChangePasswordWithOTPRequest
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			responses.BadRequest(w, "invalid_json", "Invalid JSON")
			return
		}
		secret := os.Getenv("ALTCHA_HMAC_KEY")
			ok, errCaptcha := altcha.VerifySolution(req.CaptchaValue, secret, true)
			if errCaptcha != nil || !ok {
				responses.Unauthorized(w, "invalid_altcha", "Invalid Altcha value or expired")
				return
			}
   valid:=utils.PasswordValidator(req.NewPassword)
    if valid == false {
    responses.BadRequest(w, "invalid_password", "Password must be between 12 and 36 characters long, contain at least one lowercase letter, one uppercase letter, one number, and one special character.")
    return
    }
    verifyPayload, _ := json.Marshal(map[string]string{
		"queue_id": req.ID,
		"otp":      req.OTP,
	})
	
	err := db.RDB.RPush(ctx, "verify_recovery_otp", verifyPayload).Err()
	if err != nil {
		responses.ServerError(w)
		return
	}	
	responseKey := "RESPONSE/RECOVERY/" + req.ID
	if _, err := uuid.Parse(req.ID); err != nil {
    responses.BadRequest(w, "otp_expired", "OTP expired or verification timeout")
    return
}

isFake, _ := db.RDB.Exists(ctx, "fake_queue:"+req.ID).Result()
if isFake > 0 {
    fakeKey := "fake_queue_attempts:"+req.ID
    attempts, _ := db.RDB.Incr(ctx, fakeKey).Result()
    db.RDB.Expire(ctx, fakeKey, 30*time.Minute)
    if attempts >= 3 {
        db.RDB.Del(ctx, "fake_queue:"+req.ID)
        db.RDB.Del(ctx, fakeKey)
        responses.BadRequest(w, "otp_expired", "OTP expired or verification timeout")
        return
    }
    responses.BadRequest(w, "invalid_otp", fmt.Sprintf("Invalid OTP. Attempts left: %d", 3-int(attempts)))
    return
}
	result, err := db.RDB.BLPop(ctx, 5*time.Second, responseKey).Result()
		if err != nil {
			responses.BadRequest(w, "otp_expired", "OTP expired or verification timeout")
			return
		}
		var otpRes struct {
			Valid             bool   `json:"valid"`
			Reason            string `json:"reason"`
			RemainingAttempts int    `json:"remaining_attempts"`
		}
		json.Unmarshal([]byte(result[1]), &otpRes)

		if !otpRes.Valid {
			responses.BadRequest(w, otpRes.Reason, fmt.Sprintf("Invalid OTP. Attempts left: %d", otpRes.RemainingAttempts))
			return
		}
		hashedPassword, err := passwords.GenerateHash(req.NewPassword)
			if err != nil {
				responses.ServerError(w)
				return
			}

			collection := db.MongoDB.Collection("users")
			tokcollection := db.MongoDB.Collection("tokens")
			filter := bson.M{"password_recovery.queue_id": req.ID} 
			var user bson.M
			errus := collection.FindOne(ctx, filter).Decode(&user)
			if errus != nil {
				responses.ServerError(w)
				return
			}
			update := bson.M{
				"$set": bson.M{
					"password":                  hashedPassword,
					"requestedpasswordrecovery": false,
				},
				"$unset": bson.M{
					"password_recovery": "", 
				},
			}

			_, err = collection.UpdateOne(ctx, filter, update)
			oid, ok := user["_id"].(primitive.ObjectID)
			if err != nil {
				responses.ServerError(w)
				return
			}
			if !ok {
				responses.ServerError(w)
			    return
			}
			_, _ = tokcollection.UpdateMany(ctx,
            bson.M{
            "user_id":    oid.Hex(), 
        },
            bson.M{"$set": bson.M{
                "banned":     true,
            }},
        )
 responses.OK(w, "ok")
    return
}