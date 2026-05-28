package bootguard

import (
	"context"
	"errors"
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

// trialSentinel is a marker kernel arg added to the trial entry. The confirm
// step greps /proc/cmdline for it to tell whether the trial actually booted
// (promote) or the host fell back to the saved default (clean up).
const trialSentinel = "kensa_bootguard_trial"

// paramAppliedPath records the real param so the confirm step can make it
// permanent on the default entry when it promotes.
const paramAppliedPath = StateDir + "/param_applied"

// ubuntuTrialScript is the /etc/grub.d/ script that emits the cloned trial
// menuentry on Ubuntu. The prefix MUST sort AFTER 10_linux so the real default
// stays menu index 0: with GRUB_DEFAULT=0 a failed trial's next boot falls back
// to index 0, which must be the known-good default, NOT the trial. A 09_ prefix
// (before 10_linux) made the trial index 0 and would boot-loop a failed trial
// instead of falling back — caught while validating the Ubuntu fallback path.
// The one-shot references the trial by title, so its menu index is irrelevant
// to arming.
const ubuntuTrialScript = "/etc/grub.d/11_kensa_bootguard"

// ArmOneshot stages param on a one-shot TRIAL boot entry — a clone of the
// current default plus param and a sentinel arg — and arms it as the next boot
// only. The saved default is left untouched, so if the trial boot fails the
// (already-consumed) one-shot lets the next boot fall back to the known-good
// default. Crucially there is no boot-time script to run on recovery: a kernel
// that panics is recovered by the bootloader selecting the old entry, not by
// any code executing on the broken boot. Returns the trial entry title. Must
// run over a privileged (Sudo) transport.
func ArmOneshot(ctx context.Context, t api.Transport, flavor Flavor, param string) (string, error) {
	if strings.TrimSpace(param) == "" {
		return "", fmt.Errorf("bootguard: ArmOneshot: empty param")
	}
	switch flavor {
	case FlavorBLS:
		if err := armOneshotBLS(ctx, t, param); err != nil {
			return "", err
		}
	case FlavorLegacy:
		if err := armOneshotLegacy(ctx, t, param); err != nil {
			return "", err
		}
	default:
		return "", fmt.Errorf("bootguard: ArmOneshot: unsupported flavor %q", flavor)
	}
	if err := recordTrial(ctx, t, param); err != nil {
		return "", err
	}
	return trialTitle, nil
}

// armOneshotBLS (RHEL): clone the default entry via grubby --copy-default with
// the param + sentinel, then arm the one-shot with grub2-reboot.
func armOneshotBLS(ctx context.Context, t api.Transport, param string) error {
	res, err := t.Run(ctx, "grubby --default-kernel")
	if err != nil {
		return fmt.Errorf("bootguard: grubby --default-kernel: transport error: %w", err)
	}
	if !res.OK() {
		return fmt.Errorf("bootguard: grubby --default-kernel failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	defaultKernel := strings.TrimSpace(res.Stdout)
	if defaultKernel == "" {
		return errors.New("bootguard: grubby returned no default kernel")
	}
	trialArgs := param + " " + trialSentinel
	create := fmt.Sprintf("grubby --add-kernel=%s --copy-default --args=%s --title=%s",
		shellQuote(defaultKernel), shellQuote(trialArgs), shellQuote(trialTitle))
	if _, err := runOK(ctx, t, create); err != nil {
		return err
	}
	_, err = runOK(ctx, t, "grub2-reboot "+shellQuote(trialTitle))
	return err
}

// armOneshotLegacy (Ubuntu): clone the default grub.cfg menuentry verbatim,
// retitle it, append the param + sentinel to its linux line, emit it via a
// /etc/grub.d/ script, update-grub, then arm the one-shot with grub-reboot.
func armOneshotLegacy(ctx context.Context, t api.Transport, param string) error {
	res, err := t.Run(ctx, "cat /boot/grub/grub.cfg")
	if err != nil {
		return fmt.Errorf("bootguard: reading grub.cfg: transport error: %w", err)
	}
	if !res.OK() {
		return fmt.Errorf("bootguard: cannot read grub.cfg (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	block, err := extractDefaultMenuentry(res.Stdout)
	if err != nil {
		return err
	}
	trial := buildUbuntuTrialEntry(block, param)
	script := "#!/bin/sh\nexec cat <<'KENSA_BOOTGUARD_EOF'\n" + trial + "\nKENSA_BOOTGUARD_EOF\n"
	if err := writeRemoteFile(ctx, t, ubuntuTrialScript, script); err != nil {
		return err
	}
	if _, err := runOK(ctx, t, "chmod 0755 "+shellQuote(ubuntuTrialScript)); err != nil {
		return err
	}
	if _, err := runOK(ctx, t, "update-grub"); err != nil {
		return err
	}
	_, err = runOK(ctx, t, "grub-reboot "+shellQuote(trialTitle))
	return err
}

// recordTrial stages the trial title + the real param for the confirm step.
func recordTrial(ctx context.Context, t api.Transport, param string) error {
	if _, err := runOK(ctx, t, "mkdir -p "+shellQuote(StateDir)); err != nil {
		return err
	}
	if err := writeRemoteFile(ctx, t, trialIDPath, trialTitle+"\n"); err != nil {
		return err
	}
	return writeRemoteFile(ctx, t, paramAppliedPath, param+"\n")
}

// extractDefaultMenuentry returns the first top-level menuentry block from a
// grub.cfg (GRUB_DEFAULT=0 boots the first entry), from its `menuentry` line
// through the matching closing brace.
func extractDefaultMenuentry(cfg string) (string, error) {
	lines := strings.Split(cfg, "\n")
	start := -1
	for i, ln := range lines {
		if strings.HasPrefix(strings.TrimSpace(ln), "menuentry ") {
			start = i
			break
		}
	}
	if start < 0 {
		return "", errors.New("bootguard: no menuentry found in grub.cfg")
	}
	var b []string
	for i := start; i < len(lines); i++ {
		b = append(b, lines[i])
		if i > start && strings.TrimSpace(lines[i]) == "}" {
			return strings.Join(b, "\n"), nil
		}
	}
	return "", errors.New("bootguard: unterminated menuentry block in grub.cfg")
}

// buildUbuntuTrialEntry clones a menuentry block into the trial: retitle it and
// append the param + sentinel to its linux line. Other boot-critical lines
// (search/set root, initrd, gfxmode) are preserved verbatim.
func buildUbuntuTrialEntry(block, param string) string {
	lines := strings.Split(block, "\n")
	for i, ln := range lines {
		trimmed := strings.TrimSpace(ln)
		switch {
		case strings.HasPrefix(trimmed, "menuentry "):
			lines[i] = "menuentry '" + trialTitle + "' {"
		case strings.HasPrefix(trimmed, "linux ") || strings.HasPrefix(trimmed, "linux\t"):
			lines[i] = strings.TrimRight(ln, " \t") + " " + param + " " + trialSentinel
		}
	}
	return strings.Join(lines, "\n")
}
