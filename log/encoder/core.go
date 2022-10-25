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
	"github.com/taliesins/traefik-plugin-oidc/log/level"
	"github.com/taliesins/traefik-plugin-oidc/log/syncer"
	"io"
)

// Core is a minimal, fast logger interface. It's designed for library authors
// to wrap in a more user-friendly API.
type Core interface {
	//level.LevelEnabler

	Enabled(level.Level) bool

	// With adds structured context to the Core.
	With([]Field) Core
	// Check determines whether the supplied Entry should be logged (using the
	// embedded LevelEnabler and possibly some extra logic). If the entry
	// should be logged, the Core adds itself to the CheckedEntry and returns
	// the result.
	//
	// Callers must use Check before calling Write.
	Check(Entry, *CheckedEntry) *CheckedEntry
	// Write serializes the Entry and any Fields supplied at the log site and
	// writes them to their destination.
	//
	// If called, Write should always log the Entry and Fields; it should not
	// replicate the logic of Check.
	Write(Entry, []Field) error
	// Sync flushes buffered logs (if any).
	Sync() error
}

type nopCore struct{}

// NewNopCore returns a no-op Core.
func NewNopCore() Core                                        { return nopCore{} }
func (nopCore) Enabled(level.Level) bool                      { return false }
func (n nopCore) With([]Field) Core                           { return n }
func (nopCore) Check(_ Entry, ce *CheckedEntry) *CheckedEntry { return ce }
func (nopCore) Write(Entry, []Field) error                    { return nil }
func (nopCore) Sync() error                                   { return nil }

// NewCore creates a Core that writes logs to a WriteSyncer.
func NewCore(enc Encoder, ws syncer.WriteSyncer, enab level.LevelEnabler) Core {
	return &ioCore{
		enab: enab,
		enc:  enc,
		out:  ws,
	}
}

type ioCore struct {
	enab level.LevelEnabler
	enc  Encoder
	out  syncer.WriteSyncer
}

var (
	_ Core                 = (*ioCore)(nil)
	_ level.LeveledEnabler = (*ioCore)(nil)
)

func (c *ioCore) Enabled(level level.Level) bool {
	return c.enab.Enabled(level)
}

func (c *ioCore) Level() level.Level {
	return level.LevelOf(c.enab)
}

func (c *ioCore) With(fields []Field) Core {
	clone := c.clone()
	AddFields(clone.enc, fields)
	return clone
}

func (c *ioCore) Check(ent Entry, ce *CheckedEntry) *CheckedEntry {
	if c.Enabled(ent.Level) {
		return ce.AddCore(ent, c)
	}
	return ce
}

func (c *ioCore) Write(ent Entry, fields []Field) error {

	buf, err := c.enc.EncodeEntry(ent, fields)
	if err != nil {
		return err
	}
	if c.out != nil {
		var ioWriter io.Writer
		ioWriter = c.out
		_, err = ioWriter.Write(buf.Bytes())
	}
	buf.Free()
	if err != nil {
		return err
	}
	if ent.Level > level.ErrorLevel {
		// Since we may be crashing the program, sync the output. Ignore Sync
		// errors, pending a clean solution to issue #370.
		c.Sync()
	}
	return nil
}

func (c *ioCore) Sync() error {
	if c.out == nil {
		return nil
	}
	return c.out.Sync()
}

func (c *ioCore) clone() *ioCore {
	return &ioCore{
		enab: c.enab,
		enc:  c.enc.Clone(),
		out:  c.out,
	}
}
