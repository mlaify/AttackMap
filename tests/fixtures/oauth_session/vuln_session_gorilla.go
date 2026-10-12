package web

import "github.com/gorilla/sessions"

var store = sessions.NewCookieStore([]byte("super-secret"))
