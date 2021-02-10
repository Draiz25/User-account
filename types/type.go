package types

//User is the struct for the user details
type User struct {
	ID       int    `json: ""id`
	Email    string `json: "email"`
	Password string `json "password"`
}

//Jwt is the struct for the token
type Jwt struct {
	Token string `json:"token"`
}

//Error is the struct for the error message in the token
type Error struct {
	Message string `json: "message"`
}
