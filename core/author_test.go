package core

import (
	"testing"
	"time"
)

func TestAuthor(t *testing.T) {

	author := NewJWTAuthor(time.Second*3, "tangthinker")

	token, err := author.AuthString("tangthinker", "tangthinker")

	if err != nil {
		t.Error(err)
		return
	}

	t.Logf("token: %s", token)

	time.Sleep(time.Second * 2)

	id, info, err := author.Verify(token)
	if err != nil {
		t.Error(err)
		return
	}

	t.Logf("id: %s, info: %s", id, info)

}
