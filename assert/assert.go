// Package assert provides convenience assert methods to complement
// the built in go testing library. It's intended to add onto standard
// Go tests. Example usage:
//
//	func TestSomething(t *testing.T) {
//		i, err := doSomething()
//		assert.NoErr(t, err)
//		assert.Equal(t, i, 123, "returned integer")
//	}
package assert

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
)

// Tester is a stub interface that *testing.T conforms to. It is used in all
// exported function calls in this assert library so that the library can be
// tested, or a caller can use a custom testing library. As said before,
// however, the most widely used implementation of this interface will
// be *testing.T. Example usage:
//
//	func TestSomething(t *testing.T) {
//		assert.Equal(t, "something", "something", "something")
//	}
type Tester interface {
	Fatalf(string, ...interface{})
}

type tHelper interface {
	Helper()
}

// frameWrapper fulfills the Tester interface and is a simple wrapper around another Tester that
// adds context about how many frames to backtrack on the call stack when identifying the source
// of a failed assertion.
type frameWrapper struct {
	t         Tester
	numFrames int
}

func (f frameWrapper) Fatalf(fmtStr string, vals ...interface{}) {
	f.t.Fatalf(fmtStr, vals...)
}

// WithFrameWrapper returns the original Tester, wrapped by a frameWrapper that adds context about
// how many frames to backtrack on the call stack when identifying the source of a failed
// assertion. If the Tester passed in is already a frameWrapper, the Tester wrapped by that
// frameWrapper is unwrapped and re-wrapped with updated context.
func WithFrameWrapper(t Tester) Tester {
	if fw, ok := t.(*frameWrapper); ok {
		return &frameWrapper{
			t:         fw.t,
			numFrames: fw.numFrames + 1,
		}
	}
	return &frameWrapper{
		t:         t,
		numFrames: 2,
	}
}

// callerStr returns a string representing the location of a failed assertion
func callerStr(t Tester) string {
	numFrames := 1
	if fw, ok := t.(*frameWrapper); ok {
		numFrames = fw.numFrames
	}
	_, file, line, _ := runtime.Caller(numFrames)
	return fmt.Sprintf("%s:%d", file, line)
}

// callerStrf returns a string with fmtStr and vals in it, prefixed
// by a callerStr representation of the code numFrames above the caller of
// this function
func callerStrf(t Tester, fmtStr string, vals ...interface{}) string {
	frameWrapper := WithFrameWrapper(t)
	caller := callerStr(frameWrapper)
	origStr := fmt.Sprintf(fmtStr, vals...)
	framesWithCaller := fmt.Sprintf("%s: %s", caller, origStr)
	runningUnderYegai := strings.Contains(caller, "traefik/yaegi@")
	if runningUnderYegai {
		fmt.Println(framesWithCaller)
	}
	return framesWithCaller
}

// True fails the test if b is false. on failure, it calls
// t.Fatalf(fmtStr, vals...)
func True(t Tester, b bool, fmtStr string, vals ...interface{}) {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}

	if !b {
		t.Fatalf(callerStrf(WithFrameWrapper(t), fmtStr, vals...))
	}
}

// False is the equivalent of True(t, !b, fmtStr, vals...).
func False(t Tester, b bool, fmtStr string, vals ...interface{}) {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}

	if b {
		t.Fatalf(callerStrf(WithFrameWrapper(t), fmtStr, vals...))
	}
}

// Nil uses reflect.DeepEqual(i, nil) to determine if i is nil. if it's not,
// Nil calls t.Fatalf explaining that the noun i is not nil when it should have
// been
func Nil(t Tester, i interface{}, noun string) {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}

	if !isNil(i) {
		t.Fatalf(callerStrf(WithFrameWrapper(t), "the given %s [%+v] was not nil when it should have been", noun, i))
	}
}

// NotNil uses reflect.DeepEqual(i, nil) to determine if i is nil.
// if it is, NotNil calls t.Fatalf explaining that the noun i is nil when it
// shouldn't have been.
func NotNil(t Tester, i interface{}, noun string) {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}

	if isNil(i) {
		t.Fatalf(callerStrf(WithFrameWrapper(t), "the given %s was nil when it shouldn't have been", noun))
	}
}

// Err calls t.Fatalf if expected is not equal to actual.
// it uses reflect.DeepEqual to determine if the errors are equal
func Error(t Tester, expected error, actual error) {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}

	if !reflect.DeepEqual(expected, actual) {
		t.Fatalf(callerStrf(WithFrameWrapper(t), "expected error %s but got %s", expected, actual))
	}
}

// ExistsErr calls t.Fatalf if err == nil. The message will explain that the error
// described by noun was nil when it shouldn't have been
func ExistsError(t Tester, err error, noun string) {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}

	if err == nil {
		t.Fatalf(callerStrf(WithFrameWrapper(t), "given error for %s was nil when it shouldn't have been", noun))
	}
}

// NoErr calls t.Fatalf if e is not nil.
func NoError(t Tester, e error) {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}

	if e != nil {
		t.Fatalf(callerStrf(WithFrameWrapper(t), "expected no error but received:\n%+v", e))
	}
}

// Equal ensures that the actual value returned from a test was equal to an
// expected. it uses reflect.DeepEqual to do so.
// name is used to describe the values being compared. it's used in the error
// string if actual != expected.
func Equal(t Tester, actual, expected interface{}, noun string) {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}

	if !objectsAreEqual(expected, actual) {
		diffValue := diff(expected, actual)
		expected, actual = formatUnequalValues(expected, actual)

		t.Fatalf(callerStrf(WithFrameWrapper(t), "%s not equal: \n"+
			"expected: %s\n"+
			"actual  : %s%s", noun, expected, actual, diffValue))
	}
}

// NotEqual asserts that the specified values are NOT equal.
//
//	assert.NotEqual(t, obj1, obj2)
//
// Pointer variable equality is determined based on the equality of the
// referenced values (as opposed to the memory addresses).
func NotEqual(t Tester, expected, actual interface{}, noun string) bool {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}

	if err := validateEqualArgs(expected, actual); err != nil {
		t.Fatalf(callerStrf(WithFrameWrapper(t), "%s Invalid operation: %#v != %#v (%s)", noun, expected, actual, err))
	}

	if objectsAreEqual(expected, actual) {
		t.Fatalf(callerStrf(WithFrameWrapper(t), "%s should not be equal", noun))
	}

	return true
}

// EqualValues asserts that two objects are equal or convertable to the same types
// and equal.
//
//	assert.EqualValues(t, uint32(123), int32(123))
func EqualValues(t Tester, expected, actual interface{}, noun string) bool {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}

	if !objectsAreEqualValues(expected, actual) {
		diffValue := diff(expected, actual)
		expected, actual = formatUnequalValues(expected, actual)

		t.Fatalf(callerStrf(WithFrameWrapper(t), "%s not equal: \n"+
			"expected: %s\n"+
			"actual  : %s%s", noun, expected, actual, diffValue))
	}

	return true
}

// NotEqualValues asserts that two objects are not equal even when converted to the same type
//
//	assert.NotEqualValues(t, obj1, obj2)
func NotEqualValues(t Tester, expected, actual interface{}, noun string) bool {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}

	if objectsAreEqualValues(expected, actual) {
		t.Fatalf(callerStrf(WithFrameWrapper(t), "%s should not be equal", noun))
	}

	return true
}

// NotEmpty asserts that the specified object is NOT empty.  I.e. not nil, "", false, 0 or either
// a slice or a channel with len == 0.
//
//	if assert.NotEmpty(t, obj) {
//	  assert.Equal(t, "two", obj[1])
//	}
func NotEmpty(t Tester, i interface{}, noun string) bool {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}

	pass := !isEmpty(i)
	if !pass {
		t.Fatalf(callerStrf(WithFrameWrapper(t), "the given %s was empty when it shouldn't have been", noun))
	}

	return pass
}

// Len asserts that the specified object has specific length.
// Len also fails if the object has a type that len() not accept.
//
//	assert.Len(t, mySlice, 3)
func Len(t Tester, object interface{}, length int, noun string) bool {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}

	ok, l := getLen(object)
	if !ok {
		t.Fatalf(callerStrf(WithFrameWrapper(t), "the given %s could not be applied builtin len()", noun))
	}

	if l != length {
		t.Fatalf(callerStrf(WithFrameWrapper(t), "the given %s should have %d item(s), but has %d", noun, length, l))
	}
	return true
}

// Regexp asserts that a specified regexp matches a string.
//
//	assert.Regexp(t, regexp.MustCompile("start"), "it's starting")
//	assert.Regexp(t, "start...$", "it's not starting")
func Regexp(t Tester, rx interface{}, str interface{}, noun string) bool {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}

	match := matchRegexp(rx, str)

	if !match {
		t.Fatalf(callerStrf(WithFrameWrapper(t), "%s should have matched \"%v\"", noun, rx))
	}

	return match
}

// NotRegexp asserts that a specified regexp does not match a string.
//
//	assert.NotRegexp(t, regexp.MustCompile("starts"), "it's starting")
//	assert.NotRegexp(t, "^start", "it's not starting")
func NotRegexp(t Tester, rx interface{}, str interface{}, noun string) bool {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}

	match := matchRegexp(rx, str)

	if match {
		t.Fatalf(callerStrf(WithFrameWrapper(t), "%s should have not matched \"%v\"", noun, rx))
	}

	return !match

}
