package sso_redirector

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
)

type MacStrength int

const (
	MacStrength_256 MacStrength = 0
	MacStrength_384 MacStrength = 1
	MacStrength_512 MacStrength = 2
)

var MacStrength_name = map[MacStrength]string{
	MacStrength_256: "256",
	MacStrength_384: "384",
	MacStrength_512: "512",
}

var MacStrength_value = map[string]MacStrength{
	"256": MacStrength_256,
	"384": MacStrength_384,
	"512": MacStrength_512,
}

func (x MacStrength) String() string {
	return MacStrength_name[x]
}

func ToMacStrength(x string) MacStrength {
	if integerValue, err := strconv.Atoi(x); err == nil {
		return MacStrength(integerValue)
	}
	return MacStrength_value[strings.ToLower(x)]
}

func (d *MacStrength) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString(`"`)
	buffer.WriteString(d.String())
	buffer.WriteString(`"`)
	return buffer.Bytes(), nil
}

func (d *MacStrength) UnmarshalJSON(b []byte) error {
	var s string
	err := json.Unmarshal(b, &s)
	if err != nil {
		var i int
		err2 := json.Unmarshal(b, &i)
		if err2 == nil {
			*d = MacStrength(i)
			return nil
		}

		return err
	}
	*d = ToMacStrength(s)
	return nil
}
