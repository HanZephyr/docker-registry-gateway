package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/hjx/docker-registry-gateway/internal/control"
)

func TestFormatStatusUsesAlignedProviderTable(t *testing.T) {
	zone := time.FixedZone("CST", 8*60*60)
	firstSuccess := time.Date(2026, 8, 19, 16, 13, 4, 0, zone)
	firstFailure := time.Date(2026, 8, 19, 16, 13, 23, 0, zone)
	secondSuccess := time.Date(2026, 8, 19, 16, 14, 47, 0, zone)
	output := formatStatus(control.Status{
		State:       "running",
		PID:         296016,
		Listeners:   []string{"0.0.0.0:5443", "[::]:5443"},
		ActivePulls: 2,
		QueuedPulls: 1,
		Providers: []control.ProviderHealth{
			{
				Name:                     "1pannel",
				ThroughputBytesPerSecond: 4.08 * (1 << 20),
				FirstByteMillis:          1184,
				Failures:                 7,
				LastSuccess:              firstSuccess,
				LastFailure:              firstFailure,
			},
			{
				Name:                  "毫秒镜像-免费版",
				AuthenticationInvalid: true,
				Failures:              8,
				LastSuccess:           secondSuccess,
			},
		},
	})

	for _, expected := range []string{
		"Gateway\n",
		"┌",
		"┬",
		"├",
		"┼",
		"└",
		"┴",
		"│ 状态",
		"│ PID",
		"│ 监听地址",
		"│ 活跃拉取",
		"│ 排队拉取",
		"Providers\n",
		"Provider",
		"吞吐",
		"最近成功",
		"1pannel",
		"4.08 MiB/s",
		formatStatusTimestamp(firstSuccess),
		"毫秒镜像-免费版",
		"认证失效",
		formatStatusTimestamp(secondSuccess),
	} {
		if !strings.Contains(output, expected) {
			t.Errorf("status output lacks %q:\n%s", expected, output)
		}
	}

	lines := strings.Split(strings.TrimSuffix(output, "\n"), "\n")
	header := findStatusLine(t, lines, "│ Provider")
	firstProvider := findStatusLine(t, lines, "1pannel")
	secondProvider := findStatusLine(t, lines, "毫秒镜像-免费版")
	for _, column := range []string{"状态", "吞吐", "首字节", "失败", "最近成功", "最近失败"} {
		headerOffset := displayWidthBefore(t, header, column)
		if firstOffset := displayWidthBefore(t, firstProvider, statusValueForColumn(column, "first", firstSuccess, firstFailure, secondSuccess)); firstOffset != headerOffset {
			t.Errorf("first provider %s offset = %d, want header offset %d:\n%s", column, firstOffset, headerOffset, output)
		}
		if secondOffset := displayWidthBefore(t, secondProvider, statusValueForColumn(column, "second", firstSuccess, firstFailure, secondSuccess)); secondOffset != headerOffset {
			t.Errorf("second provider %s offset = %d, want header offset %d:\n%s", column, secondOffset, headerOffset, output)
		}
	}
}

func TestFormatStatusAlignsEmojiNamesAndEscapesControlCharacters(t *testing.T) {
	aligned := formatStatus(control.Status{Providers: []control.ProviderHealth{
		{Name: "镜像😀AAAA"},
		{Name: "abcdefghij"},
	}})
	if !strings.Contains(aligned, "│ 镜像😀AAAA │ 可用") {
		t.Errorf("emoji provider is not aligned to an ASCII name:\n%s", aligned)
	}

	unsafeName := "unsafe\n\t\x1b[31m\u202e"
	escaped := formatStatus(control.Status{Providers: []control.ProviderHealth{{Name: unsafeName}}})
	if strings.Contains(escaped, unsafeName) {
		t.Errorf("status output contains the raw control characters:\n%s", escaped)
	}
	if !strings.Contains(escaped, `unsafe\u000A\u0009\u001B[31m\u202E`) {
		t.Errorf("status output does not render control characters visibly:\n%s", escaped)
	}
}

func TestFormatStatusKeepsEmptyProviderSectionBoxed(t *testing.T) {
	output := formatStatus(control.Status{State: "running"})
	for _, expected := range []string{"Providers\n", "┌", "│ Provider", "暂无 Provider 健康记录", "└"} {
		if !strings.Contains(output, expected) {
			t.Errorf("empty Provider table lacks %q:\n%s", expected, output)
		}
	}
}

func findStatusLine(t *testing.T, lines []string, contains string) string {
	t.Helper()
	for _, line := range lines {
		if strings.Contains(line, contains) {
			return line
		}
	}
	t.Fatalf("no line contains %q", contains)
	return ""
}

func displayWidthBefore(t *testing.T, value, needle string) int {
	t.Helper()
	index := strings.Index(value, needle)
	if index < 0 {
		t.Fatalf("%q does not contain %q", value, needle)
	}
	return displayWidth(value[:index])
}

func statusValueForColumn(column, row string, firstSuccess, firstFailure, secondSuccess time.Time) string {
	values := map[string]map[string]string{
		"first": {
			"状态":   "可用",
			"吞吐":   "4.08 MiB/s",
			"首字节":  "1184 ms",
			"失败":   "7",
			"最近成功": formatStatusTimestamp(firstSuccess),
			"最近失败": formatStatusTimestamp(firstFailure),
		},
		"second": {
			"状态":   "认证失效",
			"吞吐":   "0.00 MiB/s",
			"首字节":  "0 ms",
			"失败":   "8",
			"最近成功": formatStatusTimestamp(secondSuccess),
			"最近失败": "无",
		},
	}
	return values[row][column]
}

func formatStatusTimestamp(value time.Time) string {
	return value.Local().Format("2006-01-02 15:04:05 -07:00")
}
