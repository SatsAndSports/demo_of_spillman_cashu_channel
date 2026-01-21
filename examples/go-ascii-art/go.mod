module github.com/SatsAndSports/cdk/examples/go-ascii-art

go 1.24.4

replace github.com/SatsAndSports/cdk/spilman => ../../crates/cdk-spilman-go/spilman

require (
	github.com/SatsAndSports/cdk/spilman v0.0.0
	github.com/common-nighthawk/go-figure v0.0.0-20210622060536-734e95fb86be
)
