package device

import "testing"

func TestGetUniqID(t *testing.T) {
	uniqId := GetUniqID()
	println(uniqId)

}
