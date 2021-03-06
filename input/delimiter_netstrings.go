package input

import (
	"bytes"
	"errors"
	"strconv"
	"sync"
)

const (
	LenBuffEnd = ":"
	ValBuffEnd = ";"
	NoResult   = false
)

var (
	err        error
	mutex      *sync.Mutex = &sync.Mutex{}
	brokenErr              = errors.New("broken")
	lenIncErr              = errors.New("length-buffer-incomplete")
	lenInvErr              = errors.New("length-buffer-invalid-byte")
	lenConvErr             = errors.New("length-buffer-conversion-error")
	valIncErr              = errors.New("value-buffer-incomplete")
)

// A NetstrDelimiter detects when message lines start.
type NetstrDelimiter struct {
	Result      string
	lenBuff     bytes.Buffer
	valBuff     bytes.Buffer
	valBuffLen  int
	valBuffMode bool
	ignoreMode  bool
	brokenMode  bool
}

// NewNetstrDelimiter returns an initialized NetstrDelimiter.
func NewNetstrDelimiter() *NetstrDelimiter {
	return &NetstrDelimiter{
		lenBuff: *bytes.NewBuffer([]byte{}),
		valBuff: *bytes.NewBuffer([]byte{}),
	}
}

// Push the given byte into a buffer, return when a new result is available,
// as well as the first occurring error (if any occurred).
func (d *NetstrDelimiter) Push(b byte) (bool, error) {
	if d.brokenMode {
		return NoResult, errors.New("broken")
	}
	return d.processByte(b)
}

// Reset the NetstrDelimiter instance to its initial state.
func (d *NetstrDelimiter) Reset() {
	mutex.Lock()
	d.useLenBuff()
	mutex.Unlock()
}

// processByte checks if a byte must be processed as "length byte" or as "value byte".
func (d *NetstrDelimiter) processByte(b byte) (bool, error) {
	if d.valBuffMode {
		return d.processValByte(b)
	}
	return d.processLenByte(b)
}

// processLenBytes writes the passed byte to the "length buffer",
// unless the passed byte is the end of the "length buffer".
func (d *NetstrDelimiter) processLenByte(b byte) (bool, error) {
	if b == LenBuffEnd[0] {
		return NoResult, d.useValBuff()
	}
	if d.checkLenByte(b) {
		if err = d.lenBuff.WriteByte(b); err != nil {
			d.brokenMode = true
			return NoResult, lenIncErr
		}
		return NoResult, nil
	}
	d.brokenMode = true
	return NoResult, lenInvErr
}

// checkLenByte checks that the current byte is a digit.
func (d *NetstrDelimiter) checkLenByte(b byte) bool {
	for i := 0; i < 10; i++ {
		if strconv.Itoa(i)[0] == b {
			return true
		}
	}
	return false
}

// processValByte writess the passed byte to the "value buffer",
// unless the "value buffer length" is equal to 0.
func (d *NetstrDelimiter) processValByte(b byte) (bool, error) {
	if d.valBuffLen == 0 {
		d.useLenBuff()
		return true, nil
	}
	d.valBuffLen--
	if d.ignoreMode {
		return NoResult, nil
	}
	// If an error occurs, while writing to the buffer,
	// the current "value buffer" gets ignored.
	if err = d.valBuff.WriteByte(b); err != nil {
		d.ignoreMode = true
		return NoResult, valIncErr
	}
	return NoResult, nil
}

// useLenBuff overwrites the old result and resets values.
func (d *NetstrDelimiter) useLenBuff() {
	if d.ignoreMode {
		d.Result = ""
		d.ignoreMode = false
	} else {
		d.Result = d.valBuff.String()
	}
	d.valBuff.Reset()
	d.valBuffMode = false
}

// useValBuff converts the "length buffer" value to an integer,
// representing the "value buffer length" and resets values.
func (d *NetstrDelimiter) useValBuff() error {
	if d.valBuffLen, err = strconv.Atoi(d.lenBuff.String()); err != nil {
		d.brokenMode = true
		return lenConvErr
	}
	d.lenBuff.Reset()
	d.valBuffMode = true
	return nil
}
