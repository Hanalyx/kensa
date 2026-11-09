//go:build !linux

package ownedexec

import "errors"

type process struct{}

func prepare() error              { return errors.New("ownedexec: Linux process ownership is required") }
func bind(int) (*process, error)  { return nil, prepare() }
func (*process) close()           {}
func (*process) stopTree() error  { return prepare() }
func reapChildren() (bool, error) { return true, prepare() }
