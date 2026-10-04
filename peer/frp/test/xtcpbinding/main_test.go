// SPDX-License-Identifier: Apache-2.0
package xtcpbinding_test

import (
	"os"
	"testing"

	frplog "github.com/fatedier/frp/pkg/util/log"
)

func TestMain(m *testing.M) {
	// Initialize before any fixture starts background FRPS listener workers.
	frplog.InitLogger("console", "error", 1, true)
	os.Exit(m.Run())
}
