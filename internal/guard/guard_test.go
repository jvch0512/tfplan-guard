package guard

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func mkplan(changes ...map[string]any) []byte {
	b, _ := json.Marshal(map[string]any{"resource_changes": changes})
	return b
}

func rc(addr, typ string, actions []string, before, after map[string]any) map[string]any {
	return map[string]any{"address": addr, "type": typ, "change": map[string]any{"actions": actions, "before": before, "after": after}}
}

func review(t *testing.T, changes ...map[string]any) []Finding {
	t.Helper()
	fs, _, err := Review(mkplan(changes...))
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

func hasF(fs []Finding, rule, sev string) bool {
	for _, f := range fs {
		if f.Rule == rule && f.Severity == sev {
			return true
		}
	}
	return false
}

func TestStatefulDestroyAndReplace(t *testing.T) {
	for _, typ := range []string{"aws_db_instance", "aws_s3_bucket", "aws_kms_key", "aws_dynamodb_table", "google_sql_database_instance", "azurerm_key_vault"} {
		fs := review(t, rc("x.a", typ, []string{"delete"}, map[string]any{}, nil))
		if !hasF(fs, "TF001", "critical") {
			t.Errorf("%s destroy not flagged", typ)
		}
		fs = review(t, rc("x.a", typ, []string{"delete", "create"}, map[string]any{}, map[string]any{}))
		if len(fs) == 0 || !strings.Contains(fs[0].Message, "replaced") {
			t.Errorf("%s replace not described", typ)
		}
		fs = review(t, rc("x.a", typ, []string{"create", "delete"}, map[string]any{}, map[string]any{}))
		if !hasF(fs, "TF001", "critical") {
			t.Errorf("%s create-before-destroy replace not flagged", typ)
		}
	}
}

func TestNonStatefulDestroyIsQuiet(t *testing.T) {
	if fs := review(t, rc("x.a", "aws_instance", []string{"delete"}, map[string]any{}, nil)); len(fs) != 0 {
		t.Errorf("unexpected: %v", fs)
	}
}

func TestNoOpAndReadIgnored(t *testing.T) {
	bad := map[string]any{"storage_encrypted": false, "publicly_accessible": true}
	for _, a := range []string{"no-op", "read"} {
		if fs := review(t, rc("x.a", "aws_db_instance", []string{a}, bad, bad)); len(fs) != 0 {
			t.Errorf("%s should be ignored: %v", a, fs)
		}
	}
}

func TestSecurityGroupRule(t *testing.T) {
	mk := func(extra map[string]any) []Finding {
		after := map[string]any{"type": "ingress", "cidr_blocks": []any{"0.0.0.0/0"}, "from_port": 22.0, "to_port": 22.0, "protocol": "tcp"}
		for k, v := range extra {
			after[k] = v
		}
		return review(t, rc("aws_security_group_rule.r", "aws_security_group_rule", []string{"create"}, nil, after))
	}
	if fs := mk(nil); !hasF(fs, "TF002", "high") || !strings.Contains(fs[0].Message, "SSH (22)") {
		t.Errorf("ssh not flagged: %v", fs)
	}
	if fs := mk(map[string]any{"from_port": 3389.0, "to_port": 3389.0}); !strings.Contains(fs[0].Message, "RDP") {
		t.Errorf("rdp: %v", fs)
	}
	if fs := mk(map[string]any{"from_port": 0.0, "to_port": 65535.0}); !strings.Contains(fs[0].Message, "all ports") {
		t.Errorf("range all: %v", fs)
	}
	if fs := mk(map[string]any{"protocol": "-1", "from_port": 0.0, "to_port": 0.0}); !strings.Contains(fs[0].Message, "all ports") {
		t.Errorf("protocol -1: %v", fs)
	}
	if fs := mk(map[string]any{"from_port": 5000.0, "to_port": 7000.0}); !strings.Contains(fs[0].Message, "VNC") || !strings.Contains(fs[0].Message, "Redis") {
		t.Errorf("range containing ports: %v", fs)
	}
	if fs := mk(map[string]any{"from_port": 443.0, "to_port": 443.0}); len(fs) != 0 {
		t.Errorf("443 is fine: %v", fs)
	}
	if fs := mk(map[string]any{"cidr_blocks": []any{"10.0.0.0/8"}}); len(fs) != 0 {
		t.Errorf("private cidr is fine: %v", fs)
	}
	if fs := mk(map[string]any{"cidr_blocks": nil, "ipv6_cidr_blocks": []any{"::/0"}}); !hasF(fs, "TF002", "high") {
		t.Errorf("ipv6 open: %v", fs)
	}
	if fs := mk(map[string]any{"type": "egress"}); len(fs) != 0 {
		t.Errorf("egress ignored: %v", fs)
	}
	r := review(t, rc("aws_vpc_security_group_ingress_rule.r", "aws_vpc_security_group_ingress_rule", []string{"create"}, nil,
		map[string]any{"cidr_ipv4": "0.0.0.0/0", "from_port": 5432.0, "to_port": 5432.0, "protocol": "tcp"}))
	if !hasF(r, "TF002", "high") {
		t.Errorf("vpc ingress rule: %v", r)
	}
}

func TestSecurityGroupInlineIngress(t *testing.T) {
	after := map[string]any{"ingress": []any{
		map[string]any{"cidr_blocks": []any{"10.0.0.0/8"}, "from_port": 22.0, "to_port": 22.0, "protocol": "tcp"},
		map[string]any{"cidr_blocks": []any{"0.0.0.0/0"}, "from_port": 3306.0, "to_port": 3306.0, "protocol": "tcp"},
	}}
	fs := review(t, rc("aws_security_group.g", "aws_security_group", []string{"update"}, nil, after))
	if len(fs) != 1 || !strings.Contains(fs[0].Message, "MySQL") {
		t.Errorf("inline ingress: %v", fs)
	}
}

func policy(effect string, action, resource any) map[string]any {
	doc, _ := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{"Effect": effect, "Action": action, "Resource": resource}}})
	return map[string]any{"policy": string(doc)}
}

func TestIAMWildcards(t *testing.T) {
	typ := "aws_iam_policy"
	if !hasF(review(t, rc("p.a", typ, []string{"create"}, nil, policy("Allow", "*", "*"))), "TF003", "high") {
		t.Error("star star")
	}
	if !hasF(review(t, rc("p.a", typ, []string{"create"}, nil, policy("Allow", []any{"s3:Get*", "*"}, []any{"*"}))), "TF003", "high") {
		t.Error("star in lists")
	}
	if hasF(review(t, rc("p.a", typ, []string{"create"}, nil, policy("Allow", "*", "arn:aws:s3:::b/*"))), "TF003", "high") {
		t.Error("scoped resource is fine")
	}
	if hasF(review(t, rc("p.a", typ, []string{"create"}, nil, policy("Allow", "s3:GetObject", "*"))), "TF003", "high") {
		t.Error("scoped action is fine")
	}
	if hasF(review(t, rc("p.a", typ, []string{"create"}, nil, policy("Deny", "*", "*"))), "TF003", "high") {
		t.Error("deny star is fine")
	}
	single := map[string]any{"policy": `{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`}
	if !hasF(review(t, rc("p.a", "aws_iam_role_policy", []string{"create"}, nil, single)), "TF003", "high") {
		t.Error("single statement object")
	}
	if fs := review(t, rc("p.a", typ, []string{"create"}, nil, map[string]any{"policy": "not json"})); len(fs) != 0 {
		t.Errorf("invalid policy string: %v", fs)
	}
}

func TestPublicBuckets(t *testing.T) {
	for _, acl := range []string{"public-read", "public-read-write"} {
		if !hasF(review(t, rc("a.b", "aws_s3_bucket_acl", []string{"update"}, nil, map[string]any{"acl": acl})), "TF004", "high") {
			t.Errorf("acl %s", acl)
		}
	}
	if fs := review(t, rc("a.b", "aws_s3_bucket_acl", []string{"update"}, nil, map[string]any{"acl": "private"})); len(fs) != 0 {
		t.Errorf("private acl: %v", fs)
	}
	fs := review(t, rc("a.b", "aws_s3_bucket_public_access_block", []string{"update"}, nil, map[string]any{"block_public_acls": false, "block_public_policy": true, "ignore_public_acls": false}))
	if len(fs) != 1 || !strings.Contains(fs[0].Message, "block_public_acls, ignore_public_acls") {
		t.Errorf("public access block: %v", fs)
	}
	if fs := review(t, rc("a.b", "aws_s3_bucket_public_access_block", []string{"update"}, nil, map[string]any{"block_public_acls": true})); len(fs) != 0 {
		t.Errorf("block on: %v", fs)
	}
}

func TestEncryptionAndPublicDB(t *testing.T) {
	fs := review(t, rc("d.a", "aws_db_instance", []string{"create"}, nil, map[string]any{"storage_encrypted": false, "publicly_accessible": true}))
	if !hasF(fs, "TF005", "medium") || !hasF(fs, "TF006", "medium") {
		t.Errorf("db: %v", fs)
	}
	if fs := review(t, rc("d.a", "aws_db_instance", []string{"create"}, nil, map[string]any{"storage_encrypted": true, "publicly_accessible": false})); len(fs) != 0 {
		t.Errorf("good db: %v", fs)
	}
	if fs := review(t, rc("d.a", "aws_db_instance", []string{"create"}, nil, map[string]any{})); len(fs) != 0 {
		t.Errorf("unknown values are not flagged: %v", fs)
	}
	if !hasF(review(t, rc("v.a", "aws_ebs_volume", []string{"create"}, nil, map[string]any{"encrypted": false})), "TF005", "medium") {
		t.Error("ebs")
	}
}

func TestBulkDeletion(t *testing.T) {
	var cs []map[string]any
	for i := 0; i < 9; i++ {
		cs = append(cs, rc(fmt.Sprintf("aws_instance.i%d", i), "aws_instance", []string{"delete"}, map[string]any{}, nil))
	}
	if hasF(review(t, cs...), "TF007", "medium") {
		t.Error("9 is fine")
	}
	cs = append(cs, rc("aws_instance.i9", "aws_instance", []string{"delete"}, map[string]any{}, nil))
	if !hasF(review(t, cs...), "TF007", "medium") {
		t.Error("10 flagged")
	}
}

func TestSortingAndCount(t *testing.T) {
	fs, n, err := Review(mkplan(
		rc("b.a", "aws_ebs_volume", []string{"create"}, nil, map[string]any{"encrypted": false}),
		rc("a.a", "aws_s3_bucket", []string{"delete"}, map[string]any{}, nil),
		rc("c.a", "aws_instance", []string{"no-op"}, nil, nil),
	))
	if err != nil || n != 3 || len(fs) != 2 || fs[0].Severity != "critical" || fs[1].Severity != "medium" {
		t.Errorf("sorting: %v %d %v", fs, n, err)
	}
}

func TestBadInput(t *testing.T) {
	for _, in := range []string{"", "not json", "[]", "{}", `{"resource_changes":"x"}`} {
		if _, _, err := Review([]byte(in)); err == nil {
			t.Errorf("accepted %q", in)
		}
	}
	if fs, n, err := Review([]byte(`{"resource_changes":[]}`)); err != nil || n != 0 || len(fs) != 0 {
		t.Errorf("empty plan: %v %d %v", fs, n, err)
	}
}

func TestRank(t *testing.T) {
	if !(Rank("critical") < Rank("high") && Rank("high") < Rank("medium") && Rank("medium") < Rank("low") && Rank("zzz") > Rank("info")) {
		t.Error("rank order")
	}
}
