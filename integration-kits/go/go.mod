module github.com/cashubtc/cdk-spilman-kit-go

go 1.22

require (
	github.com/cashubtc/spilman-go/spilman v0.1.0
	github.com/mattn/go-sqlite3 v1.14.22
	gopkg.in/yaml.v3 v3.0.1
)

replace github.com/cashubtc/spilman-go/spilman => ../../crates/cdk-spilman-go/spilman
