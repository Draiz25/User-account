package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"github.com/dgrijalva/jwt-go"
	"github.com/draiz/Learning/Signing/types"
	"github.com/lib/pq"
	"github.com/subosito/gotenv"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB
var erro types.Error

func init() {
	gotenv.Load()
}

func logFatal(err error) {
	if err != nil {
		log.Fatal(err)
	}

}
func respondWithError(w http.ResponseWriter, status int, err types.Error) {
	w.WriteHeader(status)
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(err)
}
func createConnection() {
	pgUrl, err := pq.ParseURL(os.Getenv("ELEPHANTSQL_URL"))
	logFatal(err)
	db, err := sql.Open("postgres", pgUrl)

	err = db.Ping()
}

func SignUp(w http.ResponseWriter, r *http.Request) {
	var userID int
	var user types.User
	pgUrl, err := pq.ParseURL(os.Getenv("ELEPHANTSQL_URL"))
	logFatal(err)
	db, err := sql.Open("postgres", pgUrl)

	err = db.Ping()

	json.NewDecoder(r.Body).Decode(&user)

	if user.Email == "" {
		erro.Message = "Email is missing"
		respondWithError(w, http.StatusBadRequest, erro)
		return
	}
	if user.Password == "" {
		erro.Message = "Password is missing"
		respondWithError(w, http.StatusBadRequest, erro)
		return
	}
	fmt.Println(user.Email, user.Password)
	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 10)
	logFatal(err)
	user.Password = string(hash)
	fmt.Println(user.Password)
	stmt := "insert into users (email, password) values($1, $2) RETURNING id;"
	err = db.QueryRow(stmt, user.Email, user.Password).Scan(&userID)
	// er := db.QueryRow("insert into users (email,password) values($1,$2)RETURNING id;", user.Email, user.Password).Scan(&userID)
	if err != nil {
		erro.Message = "Server Error"
		respondWithError(w, http.StatusInternalServerError, erro)
		logFatal(err)
		return
	}
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userID)

}

func GenerateToken(user types.User) (string, error) {

	var err error
	secret := "secret"

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"emial": user.Email,
		"iss":   " course",
	})
	tokenString, err := token.SignedString([]byte(secret))
	logFatal(err)

	return tokenString, nil
}

func LogIn(w http.ResponseWriter, r *http.Request) {

	pgUrl, err := pq.ParseURL(os.Getenv("ELEPHANTSQL_URL"))
	logFatal(err)
	db, err := sql.Open("postgres", pgUrl)

	err = db.Ping()
	var user types.User
	var jwt types.Jwt

	json.NewDecoder(r.Body).Decode(&user)
	if user.Email == "" {
		erro.Message = "Email is missing"
		respondWithError(w, http.StatusBadRequest, erro)
		return
	}
	if user.Password == "" {
		erro.Message = "Password is missing"
		respondWithError(w, http.StatusBadRequest, erro)
		return
	}
	password := user.Password

	rows := db.QueryRow("select * from users where email=$1", user.Email)
	err = rows.Scan(&user.ID, &user.Email, &user.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			erro.Message = "The user does not exist"
			respondWithError(w, http.StatusBadRequest, erro)
			return
		} else {
			logFatal(err)
		}

	}

	hasedPassword := user.Password
	err = bcrypt.CompareHashAndPassword([]byte(hasedPassword), []byte(password))
	if err != nil {
		erro.Message = "The Password is not correct"
		respondWithError(w, http.StatusUnauthorized, erro)
		return
	}
	token, err := GenerateToken(user)
	if err != nil {
		logFatal(err)
	}

	w.WriteHeader(http.StatusOK)
	jwt.Token = token

	json.NewEncoder(w).Encode(jwt)

}

func ProtectedEndpoint(w http.ResponseWriter, r *http.Request) {

}

func TokenVerifyMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		var errorObj types.Error
		authHeader := r.Header.Get("Authorization")
		spew.Dump(authHeader)
		bearerToken := strings.Split(authHeader, " ")
		if len(bearerToken) == 2 {
			authToken := bearerToken[1]
			fmt.Println("is this working")
			spew.Dump(authToken)
			token, err := jwt.Parse(authToken, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("There was an error")
				}
				return []byte("secret"), nil
			})
			if err != nil {
				errorObj.Message = err.Error()
				respondWithError(w, http.StatusUnauthorized, errorObj)
				return
			}
			if token.Valid {
				next.ServeHTTP(w, r)
			} else {
				errorObj.Message = err.Error()
				respondWithError(w, http.StatusUnauthorized, errorObj)
				return
			}
		} else {
			errorObj.Message = "Invalid token"
			respondWithError(w, http.StatusUnauthorized, errorObj)
		}

	})

}
