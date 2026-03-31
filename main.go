package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/dillon-luong/chirpy/internal/auth"
	"github.com/dillon-luong/chirpy/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

var accessTokenExpireTime = 1 * time.Hour

// struct + struct funcs
type apiConfig struct {
	fileserverHits atomic.Int32
	db *database.Queries
	platform string
	jwtSecret string
}

type User struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email     string    `json:"email"`
	Token string `json:"token"`
	RefreshToken string `json:"refresh_token"`
	IsChirpyRed bool `json:"is_chirpy_red"`
}

type Chirp struct {
	ID uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body string `json:"body"`
	UserID uuid.UUID `json:"user_id"`
}

func (c *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func (w http.ResponseWriter, r *http.Request) {
		c.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (c *apiConfig) getHitsHandle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(fmt.Sprintf(`
<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>
	`, c.fileserverHits.Load())))
}

func (c *apiConfig) resetHandle(w http.ResponseWriter, r *http.Request) {
	// sensitive handle, only use on dev env
	if c.platform != "dev" {
		w.WriteHeader(403)
		return
	}

	c.fileserverHits.Store(0)
	c.db.DeleteAllUsers(r.Context())
}

func (c *apiConfig) createUserHandle(w http.ResponseWriter, r *http.Request) {
	type reqBody struct {
		Email string `json:"email"`
		Password string `json:"password"`
	}
	w.Header().Set("Content-Type", "application/json")

	req := reqBody{}
	unmarshalJson(r.Body, &req, w)

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("unexpected error hashing password: %v", err))
		return
	}

	user, err := c.db.CreateUser(r.Context(), database.CreateUserParams{
		Email: req.Email,
		HashedPassword: hash,
	})
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("Error creating user: %v", err))
		return
	}

	res := User {
		ID: user.ID,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
		Email: user.Email,
		IsChirpyRed: user.IsChirpyRed.Bool,
	}
	respondWithSuccess(w, 201, res)
}

func (c *apiConfig) updateUserHandle(w http.ResponseWriter, r *http.Request) {
	// check auth token and get user id (from claims)
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, 401, "no auth token")
		return
	}
	id, err := auth.ValidateJWT(token, c.jwtSecret)
	if err != nil {
		respondWithError(w, 401, "invalid token")
		return
	}

	type reqBody struct {
		Email string `json:"email"`
		Password string `json:"password"`
	}
	
	req := reqBody{}
	unmarshalJson(r.Body, &req, w)

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("unexpected error hashing password: %v", err))
		return
	}

	user, err := c.db.UpdateUser(r.Context(), database.UpdateUserParams{
		ID: id,
		Email: req.Email,
		HashedPassword: hash,
	})
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("Error creating user: %v", err))
		return
	}

	res := User {
		ID: user.ID,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
		Email: user.Email,
	}
	respondWithSuccess(w, 200, res)
}

func (c *apiConfig) loginHandle(w http.ResponseWriter, r *http.Request) {
	type reqBody struct {
		Email string `json:"email"`
		Password string `json:"password"`
	}
	w.Header().Set("Content-Type", "application/json")

	req := reqBody{}
	unmarshalJson(r.Body, &req, w)

	// check login creds
	user, err := c.db.GetUser(r.Context(), req.Email)
	if err != nil {
		respondWithError(w, 401, "Incorrect email or password") // incorrect email
		return
	}

	match, err := auth.CheckPasswordHash(req.Password, user.HashedPassword)
	if err != nil { // unexpected err in checking
		fmt.Printf("unexpected err checking password: %v", err)
		return
	}
	if !match {
		respondWithError(w, 401, "Incorrect email or password") // incorrect password
		return
	}

	// create auth token (access token/api key)
	token, err := auth.MakeJWT(user.ID, c.jwtSecret, accessTokenExpireTime)
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("error creating session token: %v", err))
		return
	}

	// create refresh token
	refreshExpireTime := time.Now().Add(60 * (24 * time.Hour))
	refreshToken, err := c.db.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
		Token: auth.MakeRefreshToken(),
		UserID: user.ID,
		ExpiresAt: refreshExpireTime,
	})
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("unexpected error creating refresh token in db: %v", err))
		return
	}

	res := User {
		ID: user.ID,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
		Email: user.Email,
		Token: token,
		RefreshToken: refreshToken.Token,
		IsChirpyRed: user.IsChirpyRed.Bool,
	}
	respondWithSuccess(w, 200, res)
}

func (c *apiConfig) createChirpHandler(w http.ResponseWriter, r *http.Request) {
	// check auth token and get user id (from claims)
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, 401, "no auth token")
		return
	}
	id, err := auth.ValidateJWT(token, c.jwtSecret)
	if err != nil {
		respondWithError(w, 401, "invalid token")
		return
	}

	type reqBody struct {
		Body string `json:"body"`
		// UserID uuid.UUID `json:"user_id"`
	}
	w.Header().Set("Content-Type", "application/json")

	req := reqBody{}
	unmarshalJson(r.Body, &req, w)
	
	// check len
	if len(req.Body) > 140 {
		respondWithError(w, 400, "Chirp is too long. Max len is 140 chars.")
		return
	}

	chirp, err := c.db.CreateChirp(r.Context(), database.CreateChirpParams{
		Body: req.Body,
		UserID: id,
	})
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("error creating chirp in db: %v", err))
		return
	}

	res := Chirp {
		ID: chirp.ID,
		Body: replaceProfanity(chirp.Body),
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
		UserID: chirp.UserID,
	}
	respondWithSuccess(w, 201, res)
}

func (c *apiConfig) getAllChirpsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	chirps, err := c.db.GetAllChirps(r.Context())
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("error getting all chirps from db: %v", err))
		return
	}

	var res []Chirp
	for _, chirp := range chirps {
		val := Chirp {
			ID: chirp.ID,
			Body: replaceProfanity(chirp.Body),
			CreatedAt: chirp.CreatedAt,
			UpdatedAt: chirp.UpdatedAt,
			UserID: chirp.UserID,
		}
		res = append(res, val)
	}

	respondWithSuccess(w, 200, res)
}

func (c *apiConfig) getChirpHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	id, err := uuid.Parse(r.PathValue("chirpID"))
	if err != nil {
		respondWithError(w, 400, fmt.Sprintf("error parsing chirp id: %v", err))
		return
	}

	chirp, err := c.db.GetChirp(r.Context(), id)
	if err != nil {
		respondWithError(w, 404, fmt.Sprintf("error getting chirp from db: %v", err))
		return
	}

	res := Chirp {
		ID: chirp.ID,
		Body: replaceProfanity(chirp.Body),
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
		UserID: chirp.UserID,
	}
	respondWithSuccess(w, 200, res)
}

func (c *apiConfig) refreshAccessHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, 400, fmt.Sprintf("error retrieving bearer token: %v", err))
		return
	}

	tokenEntry, err := c.db.GetRefreshToken(r.Context(), refreshToken)
	// check if token is valid
	if err != nil {
		// could be doesn't exist
		respondWithError(w, 500, fmt.Sprintf("error retrieving token from db: %v", err))
		return
	}
	if time.Now().After(tokenEntry.ExpiresAt) {
		respondWithError(w, 401, "expired refresh token")
		return
	}
	if tokenEntry.Revoked.Valid {
		respondWithError(w, 401, "revoked refresh token")
		return
	}

	token, err := auth.MakeJWT(tokenEntry.UserID, c.jwtSecret, accessTokenExpireTime)
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("unexpected error creating access token: %v", err))
		return
	}

	respondWithSuccess(w, 200, struct {
		Token string `json:"token"`
	}{
		Token: token,
	})
}

func (c *apiConfig) revokeRefreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, 400, fmt.Sprintf("error retrieving bearer token: %v", err))
		return
	}

	err = c.db.RevokeRefreshToken(r.Context(), refreshToken)
	if err != nil {
		respondWithError(w, 400, fmt.Sprintf("error revoking refresh token: %v", err))
		return
	}

	respondWithSuccess(w, 204, nil)
}

func (c *apiConfig) deleteChirpHandler(w http.ResponseWriter, r *http.Request) {
	// check auth token and get user id (from claims)
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, 401, "no auth token")
		return
	}
	id, err := auth.ValidateJWT(token, c.jwtSecret)
	if err != nil {
		respondWithError(w, 401, "invalid token")
		return
	}

	// get path var
	chirpId, err := uuid.Parse(r.PathValue("chirpID"))
	if err != nil {
		respondWithError(w, 400, fmt.Sprintf("missing chirp id in path: %v", err))
		return
	}

	// check if user owns chirp
	count, err := c.db.CountUserChirps(r.Context(), database.CountUserChirpsParams{
		ID: chirpId,
		UserID: id,
	})
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("error counting chirps user owns: %v", err))
		return
	}
	if count == 0 {
		respondWithError(w, 403, "no chirps associated with user")
		return
	}

	// delete chirp
	err = c.db.DeleteChirp(r.Context(), database.DeleteChirpParams{
		ID: chirpId,
		UserID: id,
	})
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("error deleting chirp: %v", err))
		return
	}

	respondWithSuccess(w, 204, nil)
}

func (c *apiConfig) polkaChirpyRedHandler(w http.ResponseWriter, r *http.Request) {
	type request struct {
		Event string `json:"event"`
		Data struct {
			User_ID string `json:"user_id"`
		} `json:"data"`
	}

	req := request{}
	unmarshalJson(r.Body, &req, w)

	event := req.Event
	if event != "user.upgraded" {
		respondWithSuccess(w, 204, nil)
		return
	}

	id, err := uuid.Parse(req.Data.User_ID)
	if err != nil {
		respondWithError(w, 400, fmt.Sprintf("error parsing user id: %v", err))
		return
	}

	_, err = c.db.UpgradeToChirpyRedUser(r.Context(), id)
	if err != nil {
		respondWithError(w, 404, fmt.Sprintf("user could not be found: %v", err))
		return
	}

	respondWithSuccess(w, 204, nil)
}

// main

func main() {
	// setup db connection
	godotenv.Load() // load .env file into env vars
	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		fmt.Printf("Error opening db: %v", err)
		return
	}
	dbQueries := database.New(db)

	apiCfg := apiConfig{}
	apiCfg.db = dbQueries
	apiCfg.platform = os.Getenv("PLATFORM")
	apiCfg.jwtSecret = os.Getenv("JWT_SECRET")
	
	serveMux := http.NewServeMux() // http request multiplexer
	// added handler for "/" request which just gives filesystem contents at "." dir
	// assuming any requests involving "/" will build off of it as if "/" = "."
	// if file not specified (url ending in library), will auto pick index.html
	serveMux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(".")))))
	serveMux.HandleFunc("GET /api/healthz", readyHandle);
	serveMux.HandleFunc("GET /admin/metrics", apiCfg.getHitsHandle)
	serveMux.HandleFunc("POST /admin/reset", apiCfg.resetHandle)
	serveMux.HandleFunc("POST /api/users", apiCfg.createUserHandle)
	serveMux.HandleFunc("PUT /api/users", apiCfg.updateUserHandle)
	serveMux.HandleFunc("POST /api/chirps", apiCfg.createChirpHandler)
	serveMux.HandleFunc("GET /api/chirps", apiCfg.getAllChirpsHandler)
	serveMux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.getChirpHandler)
	serveMux.HandleFunc("POST /api/login", apiCfg.loginHandle)
	serveMux.HandleFunc("POST /api/refresh", apiCfg.refreshAccessHandler)
	serveMux.HandleFunc("POST /api/revoke", apiCfg.revokeRefreshTokenHandler)
	serveMux.HandleFunc("DELETE /api/chirps/{chirpID}", apiCfg.deleteChirpHandler)
	serveMux.HandleFunc("POST /api/polka/webhooks", apiCfg.polkaChirpyRedHandler)

	// most values are optional or I'm leaving them as zero values
	server := &http.Server{
		Addr: ":8080",
		Handler: serveMux,
	}

	// start server, listening for requests from :8080
	err = server.ListenAndServe()
	if err != nil {
		fmt.Printf("err starting server listening to :8080 :%v", err)
	}
}

// handle funcs

func readyHandle(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte("OK"))
}

// helper funcs

func replaceProfanity(body string) string {
	profaneWords := []string{"kerfuffle", "sharbert", "fornax"}
	split := strings.Split(body, " ")
	for idx, val := range split {
		if slices.Contains(profaneWords, strings.ToLower(val)) {
			split[idx] = "****"
		}
	}

	return strings.Join(split, " ")
}

func unmarshalJson(body io.Reader, params any, w http.ResponseWriter) {
	decoder := json.NewDecoder(body)
	err := decoder.Decode(params)
	if err != nil {
		respondWithError(w, 400, fmt.Sprintf("Error unmarshaling data: %v", err))
	}
}

func respondWithError(w http.ResponseWriter, code int, msg string) {
	type errorReturn struct {
		Error string `json:"error"`
	}
	ret := errorReturn {
		Error: msg,
	}

	respondWithSuccess(w, code, ret)
}

func respondWithSuccess(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)

	dat, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("error marhsalling: %v", err)
		w.WriteHeader(500)
		return
	}

	if code != 204 {
		_, err = w.Write(dat)
		if err != nil {
			fmt.Printf("error writing payload: %v", err)
		}
	}
}