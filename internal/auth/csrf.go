package auth

import (
    "crypto/rand"
    "encoding/hex"
)

// RandomToken generates a cryptographically secure random token
func RandomToken(size int) (string, error) {
    buf := make([]byte, size)
    if _, err := rand.Read(buf); err != nil {
        return "", err
    }
    return hex.EncodeToString(buf), nil
}
