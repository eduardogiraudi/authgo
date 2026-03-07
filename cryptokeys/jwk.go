package cryptokeys

import (
    "crypto/ecdsa"
        "crypto/elliptic"
    "crypto/x509"
    "encoding/base64"
        "go.mongodb.org/mongo-driver/bson"
        "math/big"
    "encoding/pem"
        "errors"
    "os"
)

func GetJWKS() (map[string]interface{}, error) {
    pubBytes, err := os.ReadFile("public_es512.pem")
    if err != nil {
        return nil, err
    }

    block, _ := pem.Decode(pubBytes)
    pub, err := x509.ParsePKIXPublicKey(block.Bytes)
    if err != nil {
        return nil, err
    }

    ecPub := pub.(*ecdsa.PublicKey)
    
    jwk := map[string]interface{}{
        "keys": []map[string]interface{}{
            {
                "kty": "EC",
                "crv": "P-521",
                "alg": "ES512",
                "use": "sig",
                "kid": "1d6eaaff-b8af-4d61-b182-c76ea1a78399", 
                "x":   base64.RawURLEncoding.EncodeToString(ecPub.X.Bytes()),
                "y":   base64.RawURLEncoding.EncodeToString(ecPub.Y.Bytes()),
            },
        },
    }
    return jwk, nil
}
func JWKToECDSAPublicKey(jwk bson.M) (*ecdsa.PublicKey, error) {
    crv, _ := jwk["crv"].(string)
    xStr, _ := jwk["x"].(string)
    yStr, _ := jwk["y"].(string)

    if crv == "" || xStr == "" || yStr == "" {
        return nil, errors.New("invalid JWK format")
    }

    var curve elliptic.Curve
    switch crv {
    case "P-256":
        curve = elliptic.P256()
    case "P-384":
        curve = elliptic.P384()
    case "P-521":
        curve = elliptic.P521()
    default:
        return nil, errors.New("unsupported curve")
    }

    xBytes, err := base64.RawURLEncoding.DecodeString(xStr)
    if err != nil {
        return nil, err
    }

    yBytes, err := base64.RawURLEncoding.DecodeString(yStr)
    if err != nil {
        return nil, err
    }

    return &ecdsa.PublicKey{
        Curve: curve,
        X:     new(big.Int).SetBytes(xBytes),
        Y:     new(big.Int).SetBytes(yBytes),
    }, nil
}