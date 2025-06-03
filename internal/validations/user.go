package validations

type SignUpRequest struct {
	Name     string `json:"name" binding:"required,min=2,max=100"`
	Lastname string `json:"lastname" binding:"required,min=2,max=100"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
}
