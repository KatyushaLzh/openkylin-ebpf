// Package schema 定义统一的结构化诊断输出。
//
// 字段严格对齐赛题"结构化输出完整性(15分)"与"证据链一致性(8分)"要求：
// 异常类型、关联对象、关键指标、异常时间窗口、疑似根因、证据链、建议性结论。
// 同一结构可序列化为 JSON / YAML / Markdown，便于机器解析与评委复核。
package schema

const (
	RootCauseCPUComputeHotspot    = "cpu.compute_hotspot"
	RootCauseCPUSchedulerPressure = "cpu.scheduler_pressure"
	RootCauseIOQueueCongestion    = "io.queue_congestion"
	RootCauseIODeviceLatency      = "io.device_latency"
	RootCauseMemReclaimPressure   = "mem.reclaim_pressure"
	RootCauseMemOOMVictim         = "mem.oom_victim"
	RootCauseLockFutexContention  = "lock.futex_contention"
	RootCauseLockKernelSyncWait   = "lock.kernel_sync_wait"
	RootCauseSyscallHighFrequency = "syscall.high_frequency"
	RootCauseSyscallHighLatency   = "syscall.high_latency"
)

// RelatedObject 关联对象：可为进程/线程，也可为块设备/文件路径（按场景取用）。
type RelatedObject struct {
	Pid         uint32 `json:"pid,omitempty" yaml:"pid,omitempty"` // 进程 ID（TGID），不是线程 ID
	Tid         uint32 `json:"tid,omitempty" yaml:"tid,omitempty"`
	Comm        string `json:"comm,omitempty" yaml:"comm,omitempty"`
	Device      string `json:"device,omitempty" yaml:"device,omitempty"`
	LockAddress uint64 `json:"lock_address,omitempty" yaml:"lock_address,omitempty"`
	Scope       string `json:"scope,omitempty" yaml:"scope,omitempty"` // process | target_tree | system
}

// TimeWindow 异常时间窗口（RFC3339）。
type TimeWindow struct {
	Start     string  `json:"start" yaml:"start"`
	End       string  `json:"end" yaml:"end"`
	ElapsedMS float64 `json:"elapsed_ms" yaml:"elapsed_ms"`
}

// Evidence 证据链中的单条证据：可回溯到具体指标 / 调用栈 / 事件。
type Evidence struct {
	Type      string      `json:"type" yaml:"type"`                               // metric | stack | event | log
	Name      string      `json:"name" yaml:"name"`                               // 证据名
	Value     interface{} `json:"value,omitempty" yaml:"value,omitempty"`         // 观测值
	Threshold interface{} `json:"threshold,omitempty" yaml:"threshold,omitempty"` // 触发阈值（若有）
	Func      string      `json:"func,omitempty" yaml:"func,omitempty"`           // 热点函数（stack 类）
	Desc      string      `json:"desc,omitempty" yaml:"desc,omitempty"`           // 说明
}

// AnomalyReport 一次异常的完整结构化诊断结果。
type AnomalyReport struct {
	AnomalyType        string                 `json:"anomaly_type" yaml:"anomaly_type"`
	RootCauseCode      string                 `json:"root_cause_code" yaml:"root_cause_code"`
	RelatedObject      RelatedObject          `json:"related_object" yaml:"related_object"`
	KeyMetrics         map[string]interface{} `json:"key_metrics" yaml:"key_metrics"`
	TimeWindow         TimeWindow             `json:"time_window" yaml:"time_window"`
	SuspectedRootCause string                 `json:"suspected_root_cause" yaml:"suspected_root_cause"`
	Confidence         float64                `json:"confidence" yaml:"confidence"`
	EvidenceChain      []Evidence             `json:"evidence_chain" yaml:"evidence_chain"`
	Suggestion         string                 `json:"suggestion" yaml:"suggestion"`
}

// RuntimeEnvironment 记录生成诊断会话的机器环境，便于复现实验结果。
type RuntimeEnvironment struct {
	Hostname      string `json:"hostname" yaml:"hostname"`
	OS            string `json:"os" yaml:"os"`
	Architecture  string `json:"architecture" yaml:"architecture"`
	KernelRelease string `json:"kernel_release" yaml:"kernel_release"`
	BTF           bool   `json:"btf" yaml:"btf"`
}

// SessionConfiguration 保存会影响判定结果的公开运行参数。
type SessionConfiguration struct {
	Scenario     string             `json:"scenario" yaml:"scenario"`
	IntervalMS   int64              `json:"interval_ms" yaml:"interval_ms"`
	Sustain      int                `json:"sustain" yaml:"sustain"`
	TargetPID    uint32             `json:"target_pid,omitempty" yaml:"target_pid,omitempty"`
	AllowPartial bool               `json:"allow_partial" yaml:"allow_partial"`
	Thresholds   map[string]float64 `json:"thresholds" yaml:"thresholds"`
}

// CollectorHealth 包含跨场景通用的内核侧开销与场景自检计数。
// Counters 可承载 duplicate_issue/completion_miss/map_update_fail 等场景指标；
// map_memory_estimated=0 才表示 MapMemoryBytes 全部来自 fdinfo 精确值。
type CollectorHealth struct {
	ProgramRuntimeNS uint64            `json:"program_runtime_ns" yaml:"program_runtime_ns"`
	ProgramRunCount  uint64            `json:"program_run_count" yaml:"program_run_count"`
	MapMemoryBytes   uint64            `json:"map_memory_bytes" yaml:"map_memory_bytes"`
	Counters         map[string]uint64 `json:"counters" yaml:"counters"`
}

// CollectorStatus 表示 collector 生命周期与健康快照。失败状态不能解释为“未发现异常”。
type CollectorStatus struct {
	Name        string           `json:"name" yaml:"name"`
	Requested   bool             `json:"requested" yaml:"requested"`
	Initialized bool             `json:"initialized" yaml:"initialized"`
	State       string           `json:"state" yaml:"state"` // ready | running | stopped | failed
	PollCount   uint64           `json:"poll_count" yaml:"poll_count"`
	LastPollAt  string           `json:"last_poll_at,omitempty" yaml:"last_poll_at,omitempty"`
	Error       string           `json:"error,omitempty" yaml:"error,omitempty"`
	HealthError string           `json:"health_error,omitempty" yaml:"health_error,omitempty"`
	Health      *CollectorHealth `json:"health,omitempty" yaml:"health,omitempty"`
}

// DiagnosticSession 是 --format json 的唯一顶层值。
type DiagnosticSession struct {
	SchemaVersion string               `json:"schema_version" yaml:"schema_version"`
	StartedAt     string               `json:"started_at" yaml:"started_at"`
	EndedAt       string               `json:"ended_at" yaml:"ended_at"`
	ElapsedMS     float64              `json:"elapsed_ms" yaml:"elapsed_ms"`
	Environment   RuntimeEnvironment   `json:"environment" yaml:"environment"`
	Configuration SessionConfiguration `json:"configuration" yaml:"configuration"`
	Collectors    []CollectorStatus    `json:"collectors" yaml:"collectors"`
	Partial       bool                 `json:"partial" yaml:"partial"`
	Reports       []AnomalyReport      `json:"reports" yaml:"reports"`
}
