package main

import (
	"bytes"
	"strings"
	"testing"
)

const sample = "../../examples/plan.json"

func do(stdin string, args ...string) (int, string, string) {
	var o, e bytes.Buffer
	c := run(args, strings.NewReader(stdin), &o, &e)
	return c, o.String(), e.String()
}

func TestExitCodes(t *testing.T) {
	cases := []struct {
		args []string
		want int
	}{
		{[]string{sample}, 0},
		{[]string{sample, "--fail-on", "critical"}, 1},
		{[]string{sample, "--fail-on", "high"}, 1},
		{[]string{sample, "--fail-on", "medium"}, 1},
		{[]string{"/no/such/file"}, 2},
		{[]string{}, 2},
		{[]string{sample, "--bogus"}, 2},
		{[]string{sample, "--fail-on", "nope"}, 2},
		{[]string{sample, "--fail-on"}, 2},
		{[]string{sample, sample}, 2},
	}
	for _, c := range cases {
		if got, _, _ := do("", c.args...); got != c.want {
			t.Errorf("%v: got %d want %d", c.args, got, c.want)
		}
	}
}

func TestStdinAndCleanPlan(t *testing.T) {
	code, out, _ := do(`{"resource_changes":[]}`, "-", "--fail-on", "medium")
	if code != 0 || !strings.HasPrefix(out, "0 resource changes, 0 findings") {
		t.Errorf("clean plan: %d %q", code, out)
	}
	if code, _, _ := do("garbage", "-"); code != 2 {
		t.Errorf("garbage stdin: %d", code)
	}
}

func TestTSV(t *testing.T) {
	_, out, _ := do("", sample, "--tsv")
	if !strings.HasPrefix(out, "# 11 resource changes, 10 findings\ncritical\tTF001\taws_db_instance.orders\t") {
		t.Errorf("tsv: %q", out[:120])
	}
}

func TestOnlyCriticalTrips(t *testing.T) {
	plan := `{"resource_changes":[{"address":"a.b","type":"aws_ebs_volume","change":{"actions":["create"],"after":{"encrypted":false}}}]}`
	if c, _, _ := do(plan, "-", "--fail-on", "high"); c != 0 {
		t.Errorf("medium must not trip high: %d", c)
	}
	if c, _, _ := do(plan, "-", "--fail-on", "medium"); c != 1 {
		t.Errorf("medium must trip medium: %d", c)
	}
}
