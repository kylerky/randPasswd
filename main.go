package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
)

// built-in mandatory character sets
const (
	lowers = "abcdefghijklmnopqrstuvwxyz"
	uppers = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits = "0123456789"

	// flags
	fLower = 'l'
	fUpper = 'u'
	fDigit = 'd'
)

var (
	rFlag string
	// the desired password length
	requestLen uint
)

func init() {
	// -add, -a
	const rUsage = "add lower-case(" +
		string(fLower) + "), upper-case letters(" +
		string(fUpper) + ") or digits(" +
		string(fDigit) + ") to the list of mandatory sets"
	var rDefault = string(fLower) + string(fUpper) + string(fDigit)
	flag.StringVar(&rFlag, "a", rDefault, rUsage+" (shorthand for add)")
	flag.StringVar(&rFlag, "add", rDefault, rUsage)

	// -length, -l
	const lUsage = "the length of the password to be generated"
	flag.UintVar(&requestLen, "l", 12, lUsage+" (shorthand for length)")
	flag.UintVar(&requestLen, "length", 12, lUsage)
}

func main() {
	flag.Parse()

	needLower := strings.ContainsRune(rFlag, fLower)
	needUpper := strings.ContainsRune(rFlag, fUpper)
	needDigit := strings.ContainsRune(rFlag, fDigit)

	var mustSets []string

	// mandatory sets
	if needLower {
		mustSets = append(mustSets, lowers)
	}
	if needUpper {
		mustSets = append(mustSets, uppers)
	}
	if needDigit {
		mustSets = append(mustSets, digits)
	}

	logger := log.New(os.Stderr, "", 0)
	if requestLen == 0 || requestLen < uint(len(mustSets)) {
		logger.Fatal("The length of the password must be possitive\n" +
			"and at least the number of mandatory sets")
	}

	// the password
	passwd := make([]byte, requestLen)
	passwdLen := uint(0)
	// select one from each mandatory set
	for _, str := range mustSets {
		index, err := randInt(len(str))
		if err != nil {
			logger.Fatal(err)
		}

		passwd[passwdLen] = str[index]
		passwdLen++
	}

	pool := ""
	for _, str := range mustSets {
		pool = pool + str
	}
	poolLen := len(pool)

	if poolLen == 0 {
		logger.Fatal("Need some bytes to select from")
	}
	// fill the rest of the password
	for i := passwdLen; i < requestLen; i++ {
		index, err := randInt(poolLen)
		if err != nil {
			logger.Fatal(err)
		}

		passwd[i] = pool[index]
	}

	err := shuffle(passwd)
	if err != nil {
		logger.Fatal(err)
	}

	fmt.Println(string(passwd))
}

// generate cryptographically secure random integer
func randInt(max int) (int, error) {
	bigMax := big.NewInt(int64(max))
	bigIndex, err := rand.Int(rand.Reader, bigMax)
	return int(bigIndex.Int64()), err
}

// shuffle the array
func shuffle(arr []byte) error {
	arrLen := len(arr)
	for i := 0; i < arrLen-1; i++ {
		index, err := randInt(arrLen - i)
		if err != nil {
			return err
		}

		// swap arr[i] and arr[i+index]
		tmp := arr[i]
		arr[i] = arr[i+index]
		arr[i+index] = tmp
	}

	return nil
}
