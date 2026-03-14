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

	"github.com/dillon-luong/chirpy/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

// struct + struct funcs
type apiConfig struct {
	fileserverHits atomic.Int32
	db *database.Queries
	platform string
}

type User struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email     string    `json:"email"`
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
	}
	w.Header().Set("Content-Type", "application/json")

	req := reqBody{}
	unmarshalJson(r.Body, &req, w)

	user, err := c.db.CreateUser(r.Context(), req.Email)
	if err != nil {
		fmt.Printf("Error creating user: %v", err)
		return
	}

	res := User {
		ID: user.ID,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
		Email: user.Email,
	}
	respondWithSuccess(w, 201, res)
}

func (c *apiConfig) createChirpHandler(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Body string `json:"body"`
		UserID uuid.UUID `json:"user_id"`
	}
	type successReturn struct {
		Body string `json:"cleaned_body"`
	}
	w.Header().Set("Content-Type", "application/json")

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, 400, fmt.Sprintf("Error unmarshaling data: %v", err))
		return
	}
	
	if len(params.Body) > 140 {
		respondWithError(w, 400, "Chirp is too long. Max len is 140 chars.")
		return
	}

	c.db.CreateChirp(r.Context(), database.CreateChirpParams{
		Body: params.Body,
		UserID: params.UserID,
	})
	ret := successReturn {
		Body: replaceProfanity(params.Body),
	}
	respondWithSuccess(w, 200, ret)
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
	
	serveMux := http.NewServeMux() // http request multiplexer
	// added handler for "/" request which just gives filesystem contents at "." dir
	// assuming any requests involving "/" will build off of it as if "/" = "."
	// if file not specified (url ending in library), will auto pick index.html
	serveMux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(".")))))
	serveMux.HandleFunc("GET /api/healthz", readyHandle);
	serveMux.HandleFunc("GET /admin/metrics", apiCfg.getHitsHandle)
	serveMux.HandleFunc("POST /admin/reset", apiCfg.resetHandle)
	serveMux.HandleFunc("POST /api/users", apiCfg.createUserHandle)
	serveMux.HandleFunc("/api/chirps", apiCfg.createChirpHandler)

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

	w.WriteHeader(code)
	ret := errorReturn {
		Error: msg,
	}

	dat, err := json.Marshal(ret)
	if err != nil {
		fmt.Printf("error marshalling: %v", err)
		w.WriteHeader(500)
		return
	}
	w.Write(dat)
}

func respondWithSuccess(w http.ResponseWriter, code int, payload interface{}) {
	w.WriteHeader(code)
	dat, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("error marhsalling: %v", err)
		w.WriteHeader(500)
		return
	}
	w.Write(dat)
}