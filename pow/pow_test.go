package pow

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGetToken(t *testing.T) {
	token, err := GetToken("45.88.195.154", "origin-fallback.nxtrace.org", "443")
	fmt.Println(token, err)
	assert.NoError(t, err, "GetToken() returned an error")
}
