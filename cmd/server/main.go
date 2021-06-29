package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/jwtauth/v5"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"github.com/joho/godotenv"
	"github.com/zmb3/spotify"
)

type Token struct {
	gorm.Model
	Token string `json:"token"`
	State string `json:"state"`
}

var spotifyApi = make(map[uint]spotify.Client)
var db *gorm.DB
var jwtAuth *jwtauth.JWTAuth

func main() {

	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Error loading .env file: %v\n", err)
	}

	db, _ = gorm.Open("sqlite3", os.Getenv("DB_FILE"))
	defer db.Close()
	db.AutoMigrate(&Token{})

	router := chi.NewRouter()
	router.Use(middleware.Logger)
	router.Use(middleware.Timeout(60 * time.Second))

	scopes := []string{
		spotify.ScopeStreaming,
		spotify.ScopeUserReadPrivate,
		spotify.ScopeUserReadEmail,
		spotify.ScopeUserReadPlaybackState,
		spotify.ScopeUserModifyPlaybackState,
		spotify.ScopeUserLibraryRead,
		spotify.ScopeUserLibraryModify,
	}

	auth := spotify.NewAuthenticator(os.Getenv("REDIRECT_URL"), scopes...)
	jwtAuth = jwtauth.New("HS256", []byte(os.Getenv("JWT_SECRET")), nil)

	router.Mount("/api", apiRouter(auth))

	bind := fmt.Sprintf("%s:%s", os.Getenv("HOST"), os.Getenv("PORT"))
	log.Printf("Starting server on %s", bind)
	http.ListenAndServe(bind, router)
}

func apiRouter(auth spotify.Authenticator) http.Handler {
	r := chi.NewRouter()

	r.Get("/hello", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello"))
	})

	r.Get("/auth", func(w http.ResponseWriter, r *http.Request) {

		code := r.URL.Query().Get("code")

		// From app
		if code == "" {
			http.Redirect(w, r, auth.AuthURL("solid"), http.StatusMovedPermanently)
			return
		}

		// From Spotify
		token, err := auth.Token("solid", r)
		if err != nil {
			http.Error(w, "Couldn't get token", http.StatusNotFound)
			return
		}

		// Add to DB and assign ID
		t := Token{Token: code, State: "solid"}
		db.Create(&t)

		client := auth.NewClient(token)
		spotifyApi[t.ID] = client

		_, jwtToken, _ := jwtAuth.Encode(map[string]interface{}{"user_id": t.ID})
		cookie := http.Cookie{
			Name:  "jwt",
			Value: jwtToken,
			Path:  "/",
		}

		http.SetCookie(w, &cookie)
		http.Redirect(w, r, os.Getenv("APP_URL"), http.StatusMovedPermanently)
	})

	r.Group(func(r chi.Router) {
		r.Use(jwtauth.Verifier(jwtAuth))
		r.Use(jwtauth.Authenticator)

		r.Get("/play", func(w http.ResponseWriter, r *http.Request) {

			// Get uid from jwt
			_, claims, _ := jwtauth.FromContext(r.Context())
			uid := int(claims["user_id"].(float64))

			// Get token from uid
			var t Token
			db.First(&t, uid)

			w.Write([]byte(fmt.Sprintf("protected area. hi %v, %v", uid, t.Token)))
		})
	})

	return r
}

// func SpotifyContext(next http.Handler) http.Handler {
// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		ctx := context.WithValue(r.Context(), "spotify")
// 	})
// }
