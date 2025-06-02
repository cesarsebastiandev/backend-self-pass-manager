package models

type MessageResponse struct {
	Message string `json:"message"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

type DecryptResponse struct {
	DecryptedPassword string `json:"decrypted_password"`
}

type EmailResponse struct {
	Email string `json:"email"`
}