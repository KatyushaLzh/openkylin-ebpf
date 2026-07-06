// Package schema 定义统一的结构化诊断输出。
//
// 字段严格对齐赛题"结构化输出完整性(15分)"与"证据链一致性(8分)"要求：
// 异常类型、关联对象、关键指标、异常时间窗口、疑似根因、证据链、建议性结论。
// 同一结构可序列化为 JSON / YAML / Markdown，便于机器解析与评委复核。
package schema

// RelatedObject 关联对象：可为进程/线程，也可为块设备/文件路径（按场景取用）。
type RelatedObject struct {
	Pid    uint32 `json:"pid,omitempty" yaml:"pid,omitempty"`
	Tid    uint32 `json:"tid,omitempty" yaml:"tid,omitempty"`
	Comm   string `json:"comm,omitempty" yaml:"comm,omitempty"`
	Device string `json:"device,omitempty" yaml:"device,omitempty"`
}

// TimeWindow 异常时间窗口（RFC3339）。
type TimeWindow struct {
	Start string `json:"start" yaml:"start"`
	End   string `json:"end" yaml:"end"`
}

// Evidence 证据链中的单条证据：可回溯到具体指标 / 调用栈 / 事件。
type Evidence struct {
	Type      string      `json:"type" yaml:"type"`                             // metric | stack | event | log
	Name      string      `json:"name" yaml:"name"`                             // 证据名
	Value     interface{} `json:"value,omitempty" yaml:"value,omitempty"`       // 观测值
	Threshold interface{} `json:"threshold,omitempty" yaml:"threshold,omitempty"` // 触发阈值（若有）
	Func      string      `json:"func,omitempty" yaml:"func,omitempty"`         // 热点函数（stack 类）
	Desc      string      `json:"desc,omitempty" yaml:"desc,omitempty"`         // 说明
}

// AnomalyReport 一次异常的完整结构化诊断结果。
type AnomalyReport struct {
	AnomalyType        string                 `json:"anomaly_type" yaml:"anomaly_type"`
	RelatedObject      RelatedObject          `json:"related_object" yaml:"related_object"`
	KeyMetrics         map[string]interface{} `json:"key_metrics" yaml:"key_metrics"`
	TimeWindow         TimeWindow             `json:"time_window" yaml:"time_window"`
	SuspectedRootCause string                 `json:"suspected_root_cause" yaml:"suspected_root_cause"`
	Confidence         float64                `json:"confidence" yaml:"confidence"`
	EvidenceChain      []Evidence             `json:"evidence_chain" yaml:"evidence_chain"`
	Suggestion         string                 `json:"suggestion" yaml:"suggestion"`
}
