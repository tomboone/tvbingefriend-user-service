package main

import "time"

type User struct {
	ID            string
	Username      string
	Email         string
	PasswordHash  string
	EmailVerified bool
	VerifyToken   string
	CreatedAt     time.Time
}
