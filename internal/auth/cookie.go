package auth

import (
    "net/http"
)

const SessionCookieName = "session_id"

// SetSessionCookie устанавливает безопасную cookie сессии
func SetSessionCookie(w http.ResponseWriter, value string, secure bool) {
    http.SetCookie(w, &http.Cookie{
        Name:     SessionCookieName,
        Value:    value,
        Path:     "/",
        HttpOnly: true,               // Запрет доступа из JavaScript
        Secure:   secure,             // Только по HTTPS (включать при наличии HTTPS)
        SameSite: http.SameSiteLaxMode, // Защита от CSRF
        MaxAge:   3600,               // 1 час
    })
}

// ReadSessionCookie читает cookie сессии из запроса
func ReadSessionCookie(r *http.Request) (string, error) {
    cookie, err := r.Cookie(SessionCookieName)
    if err != nil {
        return "", err
    }
    return cookie.Value, nil
}

// ClearSessionCookie удаляет cookie сессии (logout)
func ClearSessionCookie(w http.ResponseWriter) {
    http.SetCookie(w, &http.Cookie{
        Name:     SessionCookieName,
        Value:    "",
        Path:     "/",
        HttpOnly: true,
        Secure:   false,
        MaxAge:   -1, // Удаляем cookie
    })
}
