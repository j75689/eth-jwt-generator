package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/golang-jwt/jwt"
)

func main() {

	key := flag.String("key", "", "JWT signing key")
	file := flag.String("file", "", "JWT signing key filepath (jwt.hex in datadir)")
	expireAt := flag.Int("expireAt", 0, "JWT expire at (in seconds)")
	flag.Parse()

	if *file == "" && *key == "" {
		fmt.Println("Please provide a key or a key file")
		return
	}

	var useKey string
	var err error
	var mySigningKey []byte

	if *file != "" {
		useKey, err = readKeyFile(*file)
		if err != nil {
			fmt.Println(err)
			return
		}
		mySigningKey = []byte(useKey)
	}

	if *key != "" {
		useKey = *key
		mySigningKey = common.FromHex(useKey)
	}

	ea := time.Now().Add(time.Hour * 24 * 7)
	if *expireAt > 0 {
		ea = time.Now().Add(time.Second * time.Duration(*expireAt))
	}
	ia := time.Now().Add(time.Second * 10 * -1)

	type CustomClaims struct {
		jwt.StandardClaims
	}

	// Create the Claims
	claims := CustomClaims{
		jwt.StandardClaims{
			ExpiresAt: ea.Unix(),
			IssuedAt:  ia.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, _ := token.SignedString(mySigningKey)
	fmt.Print(ss)
}

func readKeyFile(path string) (string, error) {
	if data, err := os.ReadFile(path); err == nil {
		jwtSecret := common.FromHex(strings.TrimSpace(string(data)))
		if len(jwtSecret) == 32 {
			return string(jwtSecret), nil
		}
		return "", errors.New("invalid JWT secret")
	}
	return "", errors.New("could not read JWT secret from file")
}
