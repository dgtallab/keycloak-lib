package keycloaklib

import "fmt"

func makeError(lang string, code string, args ...interface{}) error {
	l := lang
	if l == emptyString {
		l = EN
	}
	msgMap, ok := translations[l]
	if !ok {
		msgMap = translations[EN]
	}
	msg, ok := msgMap[code]
	if !ok {
		msg = code
	}
	return fmt.Errorf(msg, args...)
}

func (ka *KeycloakClient) errorf(code string, args ...interface{}) error {
	return makeError(ka.language, code, args...)
}
