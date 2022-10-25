// Copyright (c) 2016 Uber Technologies, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package encoder

import (
	"github.com/taliesins/traefik-plugin-oidc/log/color"
	"github.com/taliesins/traefik-plugin-oidc/log/level"
)

var (
	_levelToColor = map[level.Level]color.Color{
		level.DebugLevel:  color.Magenta,
		level.InfoLevel:   color.Blue,
		level.WarnLevel:   color.Yellow,
		level.ErrorLevel:  color.Red,
		level.DPanicLevel: color.Red,
		level.PanicLevel:  color.Red,
		level.FatalLevel:  color.Red,
	}
	_unknownLevelColor = color.Red

	_levelToLowercaseColorString = make(map[level.Level]string, len(_levelToColor))
	_levelToCapitalColorString   = make(map[level.Level]string, len(_levelToColor))
)

func init() {
	for level, color := range _levelToColor {
		_levelToLowercaseColorString[level] = color.Add(level.String())
		_levelToCapitalColorString[level] = color.Add(level.CapitalString())
	}
}
