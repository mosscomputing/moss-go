package runtime

import (
	"errors"
	"fmt"
)

// BlockError is raised/returned when MOSS policy denies an action (or the
// target is outside the agent's declared behavior). The SDK raises it
// BEFORE the socket opens for HTTP egress (VAL-RUNTIME-008/014) and before
// a guarded action's body executes (VAL-RUNTIME-009).
type BlockError struct {
	Reason            string
	Action            string
	Destination       string
	DeclaredViolation bool
	PolicyVersion     string
}

func (e *BlockError) Error() string {
	dest := e.Destination
	if dest == "" {
		dest = "(no-destination)"
	}
	return fmt.Sprintf("moss: blocked %s %s: %s", e.Action, dest, e.Reason)
}

// IsBlock reports whether err is a *BlockError.
func IsBlock(err error) bool {
	var be *BlockError
	return errors.As(err, &be)
}
