package validations

type CredentialRequest struct {
	Platform    string `json:"platform" binding:"required,min=2,max=100"`
	Description string `json:"description" binding:"required,min=2,max=100"`
	Email       string `json:"email" binding:"required,email,max=100"`
	Username    *string `json:"username,omitempty" binding:"omitempty,min=2,max=100"`
	Secret      string `json:"secret" binding:"required,min=8,max=100"`
	MasterKey   string `json:"master_key" binding:"required,min=8,max=30"`
}

type MasterKeyRequest struct {
	MasterKey string `json:"master_key" binding:"required"`
}

type UpdateCredentialRequest struct {
	Platform    *string `json:"platform" binding:"omitempty,min=2,max=100"`
	Description *string `json:"description" binding:"omitempty,min=2,max=100"`
	Email       *string `json:"email" binding:"omitempty,email,max=100"`
	Username    *string `json:"username" binding:"omitempty,min=2,max=100"`
	Secret      *string `json:"secret" binding:"omitempty,min=8,max=100"`
	MasterKey   *string `json:"master_key" binding:"omitempty,min=8,max=30"`
}