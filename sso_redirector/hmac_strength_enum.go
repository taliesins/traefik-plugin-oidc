package sso_redirector

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
)

type HmacStrength int

const (
	HmacStrength_256 HmacStrength = 0
	HmacStrength_384 HmacStrength = 1
	HmacStrength_512 HmacStrength = 2
)

var HmacStrength_name = map[HmacStrength]string{
	HmacStrength_256: "256",
	HmacStrength_384: "384",
	HmacStrength_512: "512",
}

var HmacStrength_value = map[string]HmacStrength{
	"256": HmacStrength_256,
	"384": HmacStrength_384,
	"512": HmacStrength_512,
}

func (x HmacStrength) String() string {
	return HmacStrength_name[x]
}

func ToHmacStrength(x string) HmacStrength {
	if integerValue, err := strconv.Atoi(x); err == nil {
		return HmacStrength(integerValue)
	}
	return HmacStrength_value[strings.ToLower(x)]
}

func (d *HmacStrength) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString(`"`)
	buffer.WriteString(d.String())
	buffer.WriteString(`"`)
	return buffer.Bytes(), nil
}

func (d *HmacStrength) UnmarshalJSON(b []byte) error {
	var s string
	err := json.Unmarshal(b, &s)
	if err != nil {
		var i int
		err2 := json.Unmarshal(b, &i)
		if err2 == nil {
			*d = HmacStrength(i)
			return nil
		}

		return err
	}
	*d = ToHmacStrength(s)
	return nil
}
