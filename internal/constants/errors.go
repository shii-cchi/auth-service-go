package constants

const (
	ErrCreatingAccessToken     = "error creating access token"
	ErrCreatingRefreshToken    = "error creating refresh token"
	ErrCheckingClient          = "error checking client exist"
	ErrSavingTokenToDB         = "error saving refresh token to db"
	ErrUpdatingTokenInDB       = "error updating refresh token in db"
	ErrGettingTokenFromDB      = "error getting refresh token from db"
	ErrInvalidAccessToken      = "invalid access token"
	ErrInvalidRefreshToken     = "invalid refresh token"
	ErrUnexpectedSigningMethod = "unexpected signing method"
	ErrInvalidClientID         = "invalid client id"
	ErrCreatingTokens          = "error creating tokens"
	ErrRefreshTokenNotFound    = "refresh token not found"
	ErrAccessTokenNotFound     = "access token not found"
	ErrRefreshingTokens        = "error refreshing tokens"
	ErrClientIDNotFound        = "client id not found"
	ErrInvalidUUID             = "invalid uuid format"
	ErrCookieNotFound          = "cookie not found"
)
