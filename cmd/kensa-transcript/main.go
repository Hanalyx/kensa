// Command kensa-transcript records real command output from a host into a
// transcript that tests replay.
//
// A test fixture written by hand encodes what its author believed a command
// prints. When that belief is wrong the fixture agrees with the code, every
// gate passes, and the defect ships: the service handlers stored systemd's
// two unit-state properties under each other's keys for 23 releases behind a
// fixture that returned them in the order the code asked for rather than the
// order systemd emits. A recording cannot make that mistake, because it comes
// from the system rather than from the author.
//
// This is a development tool. It is not shipped in packages, and it mutates
// nothing: every command in the manifest is a read.
//
// Usage:
//
//	kensa-transcript -host 192.168.1.211 -user owadmin -os rhel9 [-sudo]
//
// The manifest lives at internal/transcript/testdata/manifest.json and lists
// the commands to record. Output lands in
// internal/transcript/testdata/transcripts/<os>.json.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/transcript"
	"github.com/Hanalyx/kensa/internal/transport/ssh"
)

// manifestEntry is one command to record.
type manifestEntry struct {
	Command string `json:"command"`
	Note    string `json:"note,omitempty"`
	// OnlyOn restricts the entry to the listed OS keys. Empty means all.
	OnlyOn []string `json:"only_on,omitempty"`
}

func main() {
	var (
		host     = flag.String("host", "", "target host (required)")
		user     = flag.String("user", "", "SSH user")
		osKey    = flag.String("os", "", "OS key for the transcript, e.g. rhel9 (required)")
		sudo     = flag.Bool("sudo", false, "run commands under sudo")
		manifest = flag.String("manifest", "internal/transcript/testdata/manifest.json", "command manifest")
		outDir   = flag.String("out", "internal/transcript/testdata/transcripts", "output directory")
		today    = flag.String("date", "", "capture date, ISO 8601 (defaults to today on the recording machine)")
	)
	flag.Parse()

	if *host == "" || *osKey == "" {
		fmt.Fprintln(os.Stderr, "kensa-transcript: -host and -os are required")
		flag.Usage()
		os.Exit(2)
	}
	if *today == "" {
		*today = time.Now().UTC().Format("2006-01-02")
	}

	if err := run(*host, *user, *osKey, *manifest, *outDir, *today, *sudo); err != nil {
		fmt.Fprintf(os.Stderr, "kensa-transcript: %v\n", err)
		os.Exit(1)
	}
}

func run(host, user, osKey, manifestPath, outDir, date string, sudo bool) error {
	entries, err := loadManifest(manifestPath, osKey)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return fmt.Errorf("manifest %s has no entries for os %q", manifestPath, osKey)
	}

	ctx := context.Background()
	tr, err := ssh.Connect(ctx, ssh.Config{Host: host, User: user, Sudo: sudo})
	if err != nil {
		return fmt.Errorf("connect %s: %w", host, err)
	}
	defer func() { _ = tr.Close() }()

	out := &transcript.Transcript{OS: osKey, CapturedAt: date}

	// Identity first: a transcript that cannot say which system produced it
	// is a fixture again.
	if rel, rerr := oneLine(ctx, tr, "grep -m1 PRETTY_NAME /etc/os-release | cut -d= -f2- | tr -d '\"'"); rerr == nil {
		out.OSRelease = rel
	}
	if v, verr := oneLine(ctx, tr, "systemctl --version | head -1"); verr == nil {
		out.Systemd = v
	}

	for _, m := range entries {
		res, rerr := tr.Run(ctx, m.Command)
		if rerr != nil {
			return fmt.Errorf("run %q: %w", m.Command, rerr)
		}
		out.Entries = append(out.Entries, transcript.Entry{
			Command:  m.Command,
			Stdout:   res.Stdout,
			Stderr:   res.Stderr,
			ExitCode: res.ExitCode,
			Note:     m.Note,
		})
		fmt.Printf("  recorded (exit %d) %s\n", res.ExitCode, m.Command)
	}

	path := filepath.Join(outDir, osKey+".json")
	if err := transcript.Save(path, out); err != nil {
		return err
	}
	fmt.Printf("wrote %s: %d command(s) from %s (%s)\n", path, len(out.Entries), host, out.OSRelease)
	return nil
}

func loadManifest(path, osKey string) ([]manifestEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	var all []manifestEntry
	if err := json.Unmarshal(data, &all); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	var kept []manifestEntry
	for _, m := range all {
		if len(m.OnlyOn) == 0 || contains(m.OnlyOn, osKey) {
			kept = append(kept, m)
		}
	}
	return kept, nil
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func oneLine(ctx context.Context, tr api.Transport, cmd string) (string, error) {
	res, err := tr.Run(ctx, cmd)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(res.Stdout), nil
}
