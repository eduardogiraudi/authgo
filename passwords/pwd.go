package passwords

import (
    "crypto/rand"
    "crypto/subtle"
    "encoding/base64"
    "fmt"
    "golang.org/x/crypto/argon2"
    "strconv"
    "strings"
    "time"
    "os"
)

type Argon2Params struct {
    Time        uint32
    Memory      uint32
    Parallelism uint8
    HashLen     uint32
    SaltLen     uint32
}

var CurrentParams = Argon2Params{
    Time:        3, //6 
    Memory:      1 << 16, // 256 MB se lo si mette a 18, a 16 è 64 (il minimo)
    Parallelism: 3,
    HashLen:     32, //128
    SaltLen:     16, //64
}

func GenerateHash(password string) (string, error) {
    start := time.Now()
    salt := make([]byte, CurrentParams.SaltLen)
    if _, err := rand.Read(salt); err != nil {
        return "", err
    }

    hash := argon2.IDKey([]byte(password+os.Getenv("PEPPER")), salt,
        CurrentParams.Time,
        CurrentParams.Memory,
        CurrentParams.Parallelism,
        CurrentParams.HashLen,
    )

    elapsed := time.Since(start)
    fmt.Printf("Hashed password in: %s\n", elapsed)

    b64Salt := base64.RawStdEncoding.EncodeToString(salt)
    b64Hash := base64.RawStdEncoding.EncodeToString(hash)

    encoded := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
        CurrentParams.Memory,
        CurrentParams.Time,
        CurrentParams.Parallelism,
        b64Salt,
        b64Hash,
    )

    return encoded, nil
}

func ComparePassword(password, encodedHash string) (bool, error) {
    parts := strings.Split(encodedHash, "$")
    if len(parts) != 6 {
        fmt.Println("Malformed hash string")
        return false,nil
    }


    params := strings.Split(parts[3], ",")
    var memory, timeCost uint32
    var parallelism uint8

    for _, p := range params {
        kv := strings.Split(p, "=")
        if len(kv) != 2 {
            fmt.Println("Malformed parameter")
            return false,nil
        }
        switch kv[0] {
        case "m":
            m, err := strconv.ParseUint(kv[1], 10, 32)
            if err != nil {
                return false, err
            }
            memory = uint32(m)
        case "t":
            t, err := strconv.ParseUint(kv[1], 10, 32)
            if err != nil {
                return false, err
            }
            timeCost = uint32(t)
        case "p":
            pval, err := strconv.ParseUint(kv[1], 10, 8)
            if err != nil {
                return false, err
            }
            parallelism = uint8(pval)
        }
    }

    salt, err := base64.RawStdEncoding.DecodeString(parts[4])
    if err != nil {
        return false, err
    }

    storedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
    if err != nil {
        return false, err
    }

    computedHash := argon2.IDKey([]byte(password+os.Getenv("PEPPER")), salt, timeCost, memory, parallelism, uint32(len(storedHash)))

    if subtle.ConstantTimeCompare(storedHash, computedHash) == 1 {
        return true, nil
    }
    return false, nil
}
