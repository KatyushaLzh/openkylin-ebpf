package collector

import "time"

// ObservationWindow is the measured interval represented by one Poll delta.
// Elapsed is carried explicitly because rates use a monotonic clock while
// Start/End are wall-clock timestamps used in reports.
type ObservationWindow struct {
	Start   time.Time
	End     time.Time
	Elapsed time.Duration
}

// NewObservationWindow builds a window ending at end from a monotonic elapsed
// duration. A non-positive duration produces an invalid window, never a
// fabricated nominal one-second interval.
func NewObservationWindow(end time.Time, elapsed time.Duration) ObservationWindow {
	if end.IsZero() || elapsed <= 0 {
		return ObservationWindow{}
	}
	return ObservationWindow{Start: end.Add(-elapsed), End: end, Elapsed: elapsed}
}

// ObservationWindowBetween is used when both wall-clock poll boundaries are
// available (CPU/I/O). It derives Elapsed from those real boundaries.
func ObservationWindowBetween(start, end time.Time) ObservationWindow {
	if start.IsZero() || end.IsZero() || !end.After(start) {
		return ObservationWindow{}
	}
	return ObservationWindow{Start: start, End: end, Elapsed: end.Sub(start)}
}

func (w ObservationWindow) Valid() bool {
	return !w.Start.IsZero() && !w.End.IsZero() && w.End.After(w.Start) && w.Elapsed > 0
}

// Extend returns the incident window from the first qualifying sample through
// the current sample. It preserves real boundaries and recomputes elapsed.
func (w ObservationWindow) Extend(current ObservationWindow) ObservationWindow {
	if !w.Valid() {
		return current
	}
	if !current.Valid() || current.End.Before(w.End) {
		return w
	}
	return ObservationWindowBetween(w.Start, current.End)
}
