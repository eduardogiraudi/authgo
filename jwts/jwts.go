package jwts

import (
	"errors"
	"fmt"
	"strings"
	"os"
		"net/http"

		"crypto/ecdsa"
"encoding/json"
	"time"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

var (
	PrivateECDSA *ecdsa.PrivateKey
	PublicECDSA  *ecdsa.PublicKey
)
type MapClaims = jwt.MapClaims
func Init() error {
	privBytes, err := os.ReadFile("private_es512.pem")
	if err != nil { return err }
	
	pubBytes, err := os.ReadFile("public_es512.pem")
	if err != nil { return err }

	PrivateECDSA, err = jwt.ParseECPrivateKeyFromPEM(privBytes)
	if err != nil { return err }

	PublicECDSA, err = jwt.ParseECPublicKeyFromPEM(pubBytes)
	return err
}

func CreateToken(claims jwt.MapClaims,headers map[string]any) (string, error) {
	claims["iat"] = jwt.NewNumericDate(time.Now())
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = jwt.NewNumericDate(time.Now().Add(10 * time.Minute))
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES512, claims)
	for key, value := range headers {
        token.Header[key] = value
    }
	return token.SignedString(PrivateECDSA)
}

func ValidateToken(tokenStr string) (*jwt.Token, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"ES512"}),
		jwt.WithExpirationRequired(),
	)

	return parser.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		return PublicECDSA, nil 
	})
}
func ValidateFirstTimeDPoP(
	dpopStr string,
	expectedHtm string,
	expectedHtu string,
) (jwt.MapClaims, *ecdsa.PublicKey, error) {

	token, _, err := new(jwt.Parser).ParseUnverified(dpopStr, jwt.MapClaims{})
	if err != nil {
		return nil, nil, fmt.Errorf("invalid token format: %w", err)
	}

	jwkMap, ok := token.Header["jwk"].(map[string]interface{})
	if !ok {
		return nil, nil, errors.New("missing 'jwk' in DPoP header")
	}

	jwkBytes, err := json.Marshal(jwkMap)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal jwk: %w", err)
	}

	key, err := jwk.ParseKey(jwkBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse jwk: %w", err)
	}

	var rawPubKey interface{}
	if err := key.Raw(&rawPubKey); err != nil {
		return nil, nil, fmt.Errorf("failed to extract raw public key: %w", err)
	}

	pubKey, ok := rawPubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, errors.New("DPoP key is not ECDSA")
	}

	parsedToken, err := jwt.Parse(dpopStr, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != "ES256" && t.Method.Alg() != "ES512" {
			return nil, fmt.Errorf("unexpected alg: %s", t.Method.Alg())
		}
		return pubKey, nil
	})

	if err != nil || !parsedToken.Valid {
		return nil, nil, fmt.Errorf("invalid DPoP signature: %w", err)
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, nil, errors.New("invalid claims type")
	}

	if claims["htm"] != expectedHtm {
		return nil, nil, fmt.Errorf("invalid htm: expected %s", expectedHtm)
	}
	if claims["htu"] != expectedHtu {
		return nil, nil, fmt.Errorf("invalid htu: expected %s", expectedHtu)
	}
	if _, ok := claims["jti"].(string); !ok {
		return nil, nil, errors.New("missing jti claim")
	}

	return claims, pubKey, nil
}
func ValidateDPoPWithKnownKey(
	dpopStr string,
	expectedHtm string,
	expectedHtu string,
	pubKey *ecdsa.PublicKey,
) (jwt.MapClaims, error) {

	parsedToken, err := jwt.Parse(dpopStr, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != "ES256" && t.Method.Alg() != "ES512" {
			return nil, fmt.Errorf("unexpected alg: %s", t.Method.Alg())
		}
		return pubKey, nil
	})

	if err != nil || !parsedToken.Valid {
		return nil, fmt.Errorf("invalid DPoP signature: %w", err)
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid claims type")
	}

	if claims["htm"] != expectedHtm {
		return nil, fmt.Errorf("invalid htm: expected %s", expectedHtm)
	}
	if claims["htu"] != expectedHtu {
		return nil, fmt.Errorf("invalid htu: expected %s", expectedHtu)
	}
	if _, ok := claims["jti"].(string); !ok {
		return nil, errors.New("missing jti claim")
	}

	return claims, nil
}
func GetClaims(r *http.Request) (jwt.MapClaims, error) {
    authHeader := r.Header.Get("Authorization")
    if authHeader == "" {
        return nil, errors.New("authorization header missing")
    }
    const prefix = "DPoP "
    if !strings.HasPrefix(strings.ToLower(authHeader), strings.ToLower(prefix)) {
        return nil, errors.New("invalid authorization scheme, expected DPoP")
    }
    tokenStr := authHeader[len(prefix):]
    token, _, err := new(jwt.Parser).ParseUnverified(tokenStr, jwt.MapClaims{})
    if err != nil {
        return nil, fmt.Errorf("error parsing token: %w", err)
    }
    claims := token.Claims.(jwt.MapClaims)
    return claims, nil
}
func ValidateTokenIgnoreClaims(tokenStr string) (jwt.MapClaims, error) {
    parser := jwt.NewParser(
        jwt.WithValidMethods([]string{"ES512"}),
        jwt.WithoutClaimsValidation(), 
    )

    token, err := parser.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
        if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
        }
        return PublicECDSA, nil
    })

    if err != nil && !errors.Is(err, jwt.ErrTokenInvalidClaims) {
        return nil, fmt.Errorf("invalid token: %w", err)
    }

    claims, ok := token.Claims.(jwt.MapClaims)
    if !ok {
        return nil, errors.New("invalid claims type")
    }

    return claims, nil
}