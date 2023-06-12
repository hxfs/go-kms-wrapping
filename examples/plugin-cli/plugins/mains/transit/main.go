package main

import (
	"fmt"
	"os"

	gkwp "github.com/hxfs/go-kms-wrapping/plugin/v2"
	"github.com/hxfs/go-kms-wrapping/wrappers/transit/v2"
)

func main() {
	if err := gkwp.ServePlugin(transit.NewWrapper()); err != nil {
		fmt.Println("Error serving plugin", err)
		os.Exit(1)
	}
	os.Exit(0)
}
