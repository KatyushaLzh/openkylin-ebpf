package collector

// HealthSnapshot is the collector-neutral health/overhead contract consumed by
// the runtime session envelope and benchmark tooling.
type HealthSnapshot struct {
	ProgramRuntimeNS uint64
	ProgramRunCount  uint64
	MapMemoryBytes   uint64
	// map_memory_estimated is always present: 0 means every map used the exact
	// fdinfo memlock charge; 1 means at least one logical-capacity fallback.
	Counters map[string]uint64
}

// HealthProvider is optional during migration. A collector that implements it
// contributes BPF runtime/run-count, map memory and scenario-specific counters
// to DiagnosticSession.collectors[].health.
type HealthProvider interface {
	HealthSnapshot() (HealthSnapshot, error)
}
