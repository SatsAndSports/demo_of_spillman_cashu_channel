module github.com/SatsAndSports/cdk/examples/go-ascii-art

go 1.24.1

replace github.com/SatsAndSports/cdk/spilman => ../../crates/cdk-spilman-go/spilman

require (
	github.com/SatsAndSports/cdk/spilman v0.0.0
	github.com/common-nighthawk/go-figure v0.0.0-20210622060536-734e95fb86be
)

require github.com/skip2/go-qrcode v0.0.0-20200617195104-da1b6568686e
