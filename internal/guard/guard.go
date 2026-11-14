// Package guard reviews a Terraform plan in JSON form.
package guard

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type Finding struct {
	Severity string
	Rule     string
	Where    string
	Message  string
}

type change struct {
	Actions []string       `json:"actions"`
	Before  map[string]any `json:"before"`
	After   map[string]any `json:"after"`
}

type resourceChange struct {
	Address string `json:"address"`
	Type    string `json:"type"`
	Change  change `json:"change"`
}

type plan struct {
	ResourceChanges []resourceChange `json:"resource_changes"`
}

var severityRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

func Rank(s string) int {
	if r, ok := severityRank[s]; ok {
		return r
	}
	return 9
}

var stateful = map[string]bool{
	"aws_db_instance": true, "aws_rds_cluster": true, "aws_s3_bucket": true, "aws_dynamodb_table": true,
	"aws_kms_key": true, "aws_efs_file_system": true, "aws_ebs_volume": true, "aws_elasticache_cluster": true,
	"aws_redshift_cluster": true, "aws_opensearch_domain": true,
	"google_sql_database_instance": true, "google_storage_bucket": true, "google_kms_crypto_key": true,
	"azurerm_mssql_database": true, "azurerm_storage_account": true, "azurerm_key_vault": true, "azurerm_postgresql_flexible_server": true,
}

var sensitivePorts = map[int]string{22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 1433: "SQL Server", 6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch", 5900: "VNC", 23: "Telnet"}

func has(actions []string, a string) bool {
	for _, x := range actions {
		if x == a {
			return true
		}
	}
	return false
}

func isDestroy(a []string) bool { return has(a, "delete") }
func isReplace(a []string) bool { return has(a, "delete") && has(a, "create") }
func isActive(a []string) bool {
	for _, x := range a {
		if x != "no-op" && x != "read" {
			return true
		}
	}
	return false
}

func str(m map[string]any, k string) string {
	if m == nil {
		return ""
	}
	s, _ := m[k].(string)
	return s
}

func boolean(m map[string]any, k string) (val bool, present bool) {
	if m == nil {
		return false, false
	}
	b, ok := m[k].(bool)
	return b, ok
}

func num(v any) (int, bool) {
	f, ok := v.(float64)
	return int(f), ok
}

func open(cidrs any) bool {
	l, _ := cidrs.([]any)
	for _, c := range l {
		if s, _ := c.(string); s == "0.0.0.0/0" || s == "::/0" {
			return true
		}
	}
	return false
}

// exposedRule inspects one ingress rule object and returns a description or "".
func exposedRule(r map[string]any) string {
	if !(open(r["cidr_blocks"]) || open(r["ipv6_cidr_blocks"]) || str(r, "cidr_ipv4") == "0.0.0.0/0" || str(r, "cidr_ipv6") == "::/0") {
		return ""
	}
	from, ok1 := num(r["from_port"])
	to, ok2 := num(r["to_port"])
	proto := str(r, "protocol")
	if proto == "-1" || proto == "all" || (ok1 && ok2 && from <= 0 && to >= 65535) || (ok1 && ok2 && from == 0 && to == 0 && (proto == "-1" || proto == "")) {
		return "all ports"
	}
	if !ok1 || !ok2 {
		return ""
	}
	var names []string
	for p, n := range sensitivePorts {
		if from <= p && p <= to {
			names = append(names, fmt.Sprintf("%s (%d)", n, p))
		}
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

func policyWildcard(doc string) bool {
	var p struct {
		Statement any `json:"Statement"`
	}
	if json.Unmarshal([]byte(doc), &p) != nil {
		return false
	}
	var stmts []any
	switch s := p.Statement.(type) {
	case []any:
		stmts = s
	case map[string]any:
		stmts = []any{s}
	}
	isStar := func(v any) bool {
		switch x := v.(type) {
		case string:
			return x == "*"
		case []any:
			for _, e := range x {
				if s, _ := e.(string); s == "*" {
					return true
				}
			}
		}
		return false
	}
	for _, s := range stmts {
		m, _ := s.(map[string]any)
		if m == nil {
			continue
		}
		if eff, _ := m["Effect"].(string); eff == "Deny" {
			continue
		}
		if isStar(m["Action"]) && isStar(m["Resource"]) {
			return true
		}
	}
	return false
}

// Review returns findings sorted by severity then address, and the number of resource changes read.
func Review(data []byte) ([]Finding, int, error) {
	var p plan
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, 0, fmt.Errorf("not a Terraform plan JSON: %v", err)
	}
	if p.ResourceChanges == nil {
		return nil, 0, fmt.Errorf("not a Terraform plan JSON: no resource_changes")
	}
	var fs []Finding
	add := func(sev, rule, where, msg string) { fs = append(fs, Finding{sev, rule, where, msg}) }
	destroyed := 0
	for _, rc := range p.ResourceChanges {
		a := rc.Change.Actions
		if !isActive(a) {
			continue
		}
		w := rc.Address
		if isDestroy(a) {
			destroyed++
			if stateful[rc.Type] {
				verb := "destroyed"
				if isReplace(a) {
					verb = "replaced (destroyed and recreated)"
				}
				add("critical", "TF001", w, fmt.Sprintf("%s will be %s: data in it is lost unless it is restored from a backup", rc.Type, verb))
			}
		}
		after := rc.Change.After
		if after == nil {
			continue
		}
		switch rc.Type {
		case "aws_security_group_rule", "aws_vpc_security_group_ingress_rule":
			if t := str(after, "type"); t == "" || t == "ingress" {
				if d := exposedRule(after); d != "" {
					add("high", "TF002", w, "ingress open to the internet on "+d)
				}
			}
		case "aws_security_group":
			if l, ok := after["ingress"].([]any); ok {
				for _, r := range l {
					if m, _ := r.(map[string]any); m != nil {
						if d := exposedRule(m); d != "" {
							add("high", "TF002", w, "ingress open to the internet on "+d)
						}
					}
				}
			}
		case "aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy":
			if policyWildcard(str(after, "policy")) {
				add("high", "TF003", w, "policy allows every action on every resource")
			}
		case "aws_s3_bucket_acl":
			if acl := str(after, "acl"); acl == "public-read" || acl == "public-read-write" {
				add("high", "TF004", w, "bucket ACL is "+acl)
			}
		case "aws_s3_bucket_public_access_block":
			var off []string
			for _, k := range []string{"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"} {
				if v, ok := boolean(after, k); ok && !v {
					off = append(off, k)
				}
			}
			if len(off) > 0 {
				add("high", "TF004", w, "public access block disabled: "+strings.Join(off, ", "))
			}
		case "aws_db_instance":
			if v, ok := boolean(after, "storage_encrypted"); ok && !v {
				add("medium", "TF005", w, "database storage is not encrypted")
			}
			if v, _ := boolean(after, "publicly_accessible"); v {
				add("medium", "TF006", w, "database is publicly accessible")
			}
		case "aws_ebs_volume":
			if v, ok := boolean(after, "encrypted"); ok && !v {
				add("medium", "TF005", w, "volume is not encrypted")
			}
		}
	}
	if destroyed >= 10 {
		add("medium", "TF007", "plan", fmt.Sprintf("%d resources will be destroyed in one plan", destroyed))
	}
	sort.SliceStable(fs, func(i, j int) bool {
		if Rank(fs[i].Severity) != Rank(fs[j].Severity) {
			return Rank(fs[i].Severity) < Rank(fs[j].Severity)
		}
		if fs[i].Where != fs[j].Where {
			return fs[i].Where < fs[j].Where
		}
		return fs[i].Rule < fs[j].Rule
	})
	return fs, len(p.ResourceChanges), nil
}
