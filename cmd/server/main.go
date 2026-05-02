package main

import (
    "log"
    "net/http"
    
    "example.com/pz6-web-security/internal/httpapi"
    "example.com/pz6-web-security/internal/store"
)

func main() {
    // Флаг secure (при использовании HTTPS должен быть true)
    secure := false // Установите true если используете HTTPS
    
    // Создаем хранилище
    st := store.New()
    
    // Создаем обработчик
    handler, err := httpapi.NewHandler(st, secure)
    if err != nil {
        log.Fatal("Failed to create handler:", err)
    }
    
    // Настраиваем маршруты
    mux := http.NewServeMux()
    mux.HandleFunc("/login", handler.Login)
    mux.HandleFunc("/profile", handler.Profile)
    mux.HandleFunc("/hello", handler.Hello)
    mux.HandleFunc("/logout", handler.Logout)
    
    // Запускаем сервер
    addr := ":8080"
    log.Printf("Server started on http://localhost%s", addr)
    log.Printf("Open http://localhost%s/login", addr)
    log.Println("")
    log.Println("Демонстрация XSS-защиты:")
    log.Println("  Попробуйте ввести в поле имени: <script>alert('xss')</script>")
    log.Println("  Скрипт НЕ выполнится, а будет отображен как текст")
    log.Println("")
    log.Println("Демонстрация CSRF-защиты:")
    log.Println("  При попытке отправить POST без csrf_token получите 403 Forbidden")
    
    if err := http.ListenAndServe(addr, mux); err != nil {
        log.Fatal("Server failed:", err)
    }
}
