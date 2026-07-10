// Command rca-report-compact compacts ebpf-rca JSON report streams.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/output"
	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/report"
	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/schema"
)

func main() {
	inPath := flag.String("input", "", "input JSON report stream; empty means stdin")
	outPath := flag.String("output", "", "output report stream; empty means stdout")
	format := flag.String("format", "json", "output format: json|jsonl|yaml|md")
	flag.Parse()

	if err := run(*inPath, *outPath, *format); err != nil {
		fmt.Fprintln(os.Stderr, "compact:", err)
		os.Exit(1)
	}
}

func run(inPath, outPath, format string) error {
	in, closeIn, err := openInput(inPath)
	if err != nil {
		return err
	}
	defer closeIn()

	out, closeOut, err := openOutput(outPath)
	if err != nil {
		return err
	}
	defer closeOut()

	data, err := io.ReadAll(in)
	if err != nil {
		return err
	}
	reports, session, err := decodeInput(data)
	if err != nil {
		return err
	}
	agg := report.New()
	for _, r := range reports {
		agg.Add(r)
	}

	if format == "json" && session != nil {
		session.Reports = agg.Reports()
		return output.WriteSession(out, *session)
	}
	for _, r := range agg.Reports() {
		writeFormat := format
		if writeFormat == "json" {
			writeFormat = "jsonl"
		}
		if err := output.Write(out, r, writeFormat); err != nil {
			return err
		}
	}
	return nil
}

func decodeInput(data []byte) ([]schema.AnomalyReport, *schema.DiagnosticSession, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, nil, fmt.Errorf("empty input")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	var raw json.RawMessage
	if err := dec.Decode(&raw); err == nil {
		var extra json.RawMessage
		if err := dec.Decode(&extra); err == io.EOF {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(raw, &fields); err != nil {
				return nil, nil, err
			}
			if _, ok := fields["reports"]; ok {
				session, err := schema.DecodeDiagnosticSessionJSON(raw)
				if err != nil {
					return nil, nil, err
				}
				return session.Reports, &session, nil
			}
			report, err := schema.DecodeAnomalyReportJSON(raw)
			if err != nil {
				return nil, nil, err
			}
			return []schema.AnomalyReport{report}, nil, nil
		}
	}

	var reports []schema.AnomalyReport
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for line := 1; scanner.Scan(); line++ {
		b := bytes.TrimSpace(scanner.Bytes())
		if len(b) == 0 {
			continue
		}
		report, err := schema.DecodeAnomalyReportJSON(b)
		if err != nil {
			return nil, nil, fmt.Errorf("JSONL line %d: %w", line, err)
		}
		reports = append(reports, report)
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}
	if len(reports) == 0 {
		return nil, nil, fmt.Errorf("no reports")
	}
	return reports, nil, nil
}

func openInput(path string) (io.Reader, func(), error) {
	if path == "" {
		return os.Stdin, func() {}, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	return f, func() { _ = f.Close() }, nil
}

func openOutput(path string) (io.Writer, func(), error) {
	if path == "" {
		return os.Stdout, func() {}, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, err
	}
	return f, func() { _ = f.Close() }, nil
}
