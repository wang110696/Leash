// `leash doctor` is the coverage self-check called for in ARCHITECTURE.md
// section 8: it verifies the things a session silently assumes are true
// (CA generation works, the proxy can actually bind a port, the policy
// file parses) so a broken environment is caught before a session starts,
// not discovered mid-run as a confusing failure.
package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/wang110696/Leash/internal/ca"
	"github.com/wang110696/Leash/internal/policy"
)

type doctorCheck struct {
	name string
	err  error
}

func runDoctor() int {
	var checks []doctorCheck

	home, err := os.UserHomeDir()
	checks = append(checks, doctorCheck{"resolve home directory", err})
	if err != nil {
		return reportDoctor(checks)
	}
	leashDir := filepath.Join(home, ".leash")

	checks = append(checks, doctorCheck{"create/access ~/.leash", os.MkdirAll(leashDir, 0o700)})

	_, _, caPaths, caErr := ca.Ensure(leashDir)
	checks = append(checks, doctorCheck{"local CA present (generated if missing)", caErr})
	if caErr == nil {
		if _, err := os.Stat(caPaths.CertPath); err != nil {
			checks = append(checks, doctorCheck{"CA cert file readable", err})
		}
	}

	ln, listenErr := net.Listen("tcp4", "127.0.0.1:0")
	checks = append(checks, doctorCheck{"can bind a local proxy port", listenErr})
	if listenErr == nil {
		ln.Close()
	}

	_, gitErr := exec.LookPath("git")
	checks = append(checks, doctorCheck{"real git binary resolvable on PATH", gitErr})

	_, policyErr := policy.Load(filepath.Join(leashDir, "policy.yaml"))
	checks = append(checks, doctorCheck{"policy.yaml parses (or absent, using defaults)", policyErr})

	return reportDoctor(checks)
}

func reportDoctor(checks []doctorCheck) int {
	ok := true
	for _, c := range checks {
		if c.err != nil {
			ok = false
			fmt.Printf("✗ %s: %v\n", c.name, c.err)
		} else {
			fmt.Printf("✓ %s\n", c.name)
		}
	}
	if ok {
		fmt.Println("\nleash: all checks passed")
		return 0
	}
	fmt.Println("\nleash: one or more checks failed — see above")
	return 1
}
