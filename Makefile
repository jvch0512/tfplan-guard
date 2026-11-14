build:
	go build -o tfplan-guard ./cmd/tfplan-guard

test:
	go vet ./... && go test ./...

sample: build
	mkdir -p docs site
	./tfplan-guard examples/plan.json > docs/sample-output.txt; true
	./tfplan-guard examples/plan.json --tsv > docs/sample-output.tsv; true
	python3 scripts/site.py docs/sample-output.tsv site/index.html "tfplan-guard" "Reviews a Terraform plan (JSON) before apply: data loss, open ports, wildcard IAM, public buckets. Go." "A synthetic plan with a mix of risky and safe changes."
