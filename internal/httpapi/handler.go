package httpapi

import (
    "html/template"
    "net/http"
    "strings"
    
    "example.com/pz6-web-security/internal/auth"
    "example.com/pz6-web-security/internal/store"
)

type Handler struct {
    store       *store.Store
    profileTmpl *template.Template
    helloTmpl   *template.Template
    secure      bool // флаг для Secure cookie (true при HTTPS)
}

func NewHandler(s *store.Store, secure bool) (*Handler, error) {
    profileTmpl, err := template.ParseFiles("templates/profile.html")
    if err != nil {
        return nil, err
    }
    
    helloTmpl, err := template.ParseFiles("templates/hello.html")
    if err != nil {
        return nil, err
    }
    
    return &Handler{
        store:       s,
        profileTmpl: profileTmpl,
        helloTmpl:   helloTmpl,
        secure:      secure,
    }, nil
}

// Login - имитация входа, установка cookie сессии
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }
    
    // Генерируем session ID
    sessionID, err := auth.RandomToken(16)
    if err != nil {
        http.Error(w, "failed to create session", http.StatusInternalServerError)
        return
    }
    
    // Генерируем CSRF токен
    csrfToken, err := auth.RandomToken(16)
    if err != nil {
        http.Error(w, "failed to create csrf token", http.StatusInternalServerError)
        return
    }
    
    // Сохраняем профиль
    h.store.Save(&store.UserProfile{
        SessionID:  sessionID,
        Name:       "Студент",
        CSRFToken:  csrfToken,
    })
    
    // Устанавливаем cookie сессии
    auth.SetSessionCookie(w, sessionID, h.secure)
    
    // Перенаправляем на профиль
    http.Redirect(w, r, "/profile", http.StatusFound)
}

// Profile - отображение и обновление профиля
func (h *Handler) Profile(w http.ResponseWriter, r *http.Request) {
    // Проверяем наличие сессии
    sessionID, err := auth.ReadSessionCookie(r)
    if err != nil {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }
    
    profile, ok := h.store.Get(sessionID)
    if !ok {
        http.Error(w, "session not found", http.StatusUnauthorized)
        return
    }
    
    switch r.Method {
    case http.MethodGet:
        // Отображаем форму профиля
        data := struct {
            Name       string
            CSRFToken  string
        }{
            Name:      profile.Name,
            CSRFToken: profile.CSRFToken,
        }
        
        if err := h.profileTmpl.Execute(w, data); err != nil {
            http.Error(w, "template error", http.StatusInternalServerError)
            return
        }
        
    case http.MethodPost:
        // Обрабатываем POST запрос (обновление имени)
        if err := r.ParseForm(); err != nil {
            http.Error(w, "bad form", http.StatusBadRequest)
            return
        }
        
        // Проверяем CSRF токен
        tokenFromForm := r.FormValue("csrf_token")
        if tokenFromForm == "" || tokenFromForm != profile.CSRFToken {
            http.Error(w, "invalid csrf token", http.StatusForbidden)
            return
        }
        
        // Получаем новое имя
        name := strings.TrimSpace(r.FormValue("name"))
        if name == "" {
            http.Error(w, "name is required", http.StatusBadRequest)
            return
        }
        
        // Обновляем имя
        h.store.UpdateName(sessionID, name)
        
        // Опционально: ротация CSRF токена (дополнительное задание)
        newCSRFToken, err := auth.RandomToken(16)
        if err == nil {
            h.store.UpdateCSRFToken(sessionID, newCSRFToken)
        }
        
        // Перенаправляем на страницу приветствия
        http.Redirect(w, r, "/hello", http.StatusFound)
        
    default:
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
    }
}

// Hello - безопасное отображение имени пользователя
func (h *Handler) Hello(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }
    
    // Проверяем наличие сессии
    sessionID, err := auth.ReadSessionCookie(r)
    if err != nil {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }
    
    profile, ok := h.store.Get(sessionID)
    if !ok {
        http.Error(w, "session not found", http.StatusUnauthorized)
        return
    }
    
    // Безопасно отображаем имя через шаблон
    data := struct {
        Name string
    }{
        Name: profile.Name,
    }
    
    if err := h.helloTmpl.Execute(w, data); err != nil {
        http.Error(w, "template error", http.StatusInternalServerError)
        return
    }
}

// Logout - завершение сессии
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }
    
    // Очищаем cookie
    auth.ClearSessionCookie(w)
    
    // Перенаправляем на страницу логина
    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    w.Write([]byte(`<!DOCTYPE html>
<html>
<head><title>Выход</title></head>
<body>
    <h1>Вы вышли из системы</h1>
    <p><a href="/login">Войти снова</a></p>
</body>
</html>`))
}
