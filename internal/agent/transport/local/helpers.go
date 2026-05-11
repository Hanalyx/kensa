package local

import (
	"errors"
	"io"
	"os/exec"
	"strings"
)

// isExitError unwraps an exec.Run error to determine if the
// command ran-and-exited-nonzero (true) vs failed-to-start
// (false). The ExitError is populated for the caller.
func isExitError(err error, target **exec.ExitError) bool {
	return errors.As(err, target)
}

// copyAndClose io.Copies src → dst and closes dst, returning
// the first non-nil error from either operation. The
// pattern matches stdlib io.Copy idiom but ensures close
// errors aren't silently dropped.
func copyAndClose(dst io.WriteCloser, src io.Reader) (int64, error) {
	n, copyErr := io.Copy(dst, src)
	closeErr := dst.Close()
	if copyErr != nil {
		return n, copyErr
	}
	return n, closeErr
}

// shellQuote single-quote-escapes s for safe inclusion in a
// sh -c invocation. Matches the bootstrap.shellQuote
// pattern. Used only in the sudo-wrap path of Transport.Run.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
