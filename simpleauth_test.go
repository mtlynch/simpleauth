package simpleauth_test

import (
	"testing"

	"github.com/mtlynch/simpleauth/v3"
)

func TestNewUserIDRejectsEmptyString(t *testing.T) {
	_, err := simpleauth.NewUserID("")

	if err == nil {
		t.Fatal("err=nil, want non-nil")
	}
}

func TestNewUserIDReturnsUserID(t *testing.T) {
	userID, err := simpleauth.NewUserID("123")
	if err != nil {
		t.Fatalf("creating user ID: %v", err)
	}

	if got, want := userID.String(), "123"; got != want {
		t.Fatalf("userID.String()=%q, want %q", got, want)
	}
}
