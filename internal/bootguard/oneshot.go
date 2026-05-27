package bootguard

import (
	"context"
	"fmt"
	"strings"

	"github.com/Hanalyx/kensa/api"
)

// trialTitle is the title of the one-shot trial boot entry the guard creates.
// A single trial is armed at a time.
const trialTitle = "kensa-bootguard-trial"

// trialIDPath records the armed trial entry's title so the confirm step can
// promote it (on a healthy boot into the trial) or remove it (on fallback).
const trialIDPath = StateDir + "/trial_entry"

// ArmOneshot implements Option B (founder-ratified 2026-05-27) for a BLS (RHEL)
// host: create a TRIAL boot entry = clone of the current default plus
// trialArgs, set it as a ONE-SHOT next boot, and record its title. The saved
// default stays the old/known-good entry, so a failed boot auto-falls back to
// it (the one-shot is consumed) with no boot-time script — which makes B safe
// for the kernel-panic case (§7.1f).
//
// RHEL/BLS only so far (grubby + grub2-reboot, validated present on RHEL
// 8.10/10.1); Ubuntu legacy is a separate increment. Must run over a privileged
// (Sudo) transport. Returns the trial entry title.
//
// Behavior (does the boot actually fall back / promote) is validated by the
// destructive reboot test, not these unit tests.
func ArmOneshot(ctx context.Context, t api.Transport, flavor Flavor, trialArgs string) (string, error) {
	if flavor != FlavorBLS {
		return "", fmt.Errorf("bootguard: ArmOneshot supports only BLS so far, got %q", flavor)
	}
	if strings.TrimSpace(trialArgs) == "" {
		return "", fmt.Errorf("bootguard: ArmOneshot: empty trialArgs")
	}

	// Resolve the current default kernel to clone.
	res, err := t.Run(ctx, "grubby --default-kernel")
	if err != nil {
		return "", fmt.Errorf("bootguard: grubby --default-kernel: transport error: %w", err)
	}
	if !res.OK() {
		return "", fmt.Errorf("bootguard: grubby --default-kernel failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	defaultKernel := strings.TrimSpace(res.Stdout)
	if defaultKernel == "" {
		return "", fmt.Errorf("bootguard: grubby returned no default kernel")
	}

	// Create the trial entry: a copy of the default plus the new args, with a
	// distinct title, WITHOUT touching the default entry. --copy-default
	// carries the default's initrd and existing args.
	create := fmt.Sprintf("grubby --add-kernel=%s --copy-default --args=%s --title=%s",
		shellQuote(defaultKernel), shellQuote(trialArgs), shellQuote(trialTitle))
	if _, err := runOK(ctx, t, create); err != nil {
		return "", err
	}

	// Arm the one-shot: boot the trial ONCE; on failure the consumed one-shot
	// falls back to the unchanged saved default.
	if _, err := runOK(ctx, t, "grub2-reboot "+shellQuote(trialTitle)); err != nil {
		return "", err
	}

	// Record the trial identity for the confirm step.
	if _, err := runOK(ctx, t, "mkdir -p "+shellQuote(StateDir)); err != nil {
		return "", err
	}
	if err := writeRemoteFile(ctx, t, trialIDPath, trialTitle+"\n"); err != nil {
		return "", err
	}
	return trialTitle, nil
}
