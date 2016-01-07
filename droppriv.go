// Copyright (c) 2014-2016 Bitmark Inc.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"os/user"
	"strconv"
	"syscall"
)

// drop privileges to user
// unfortunately there is no os/group lookup in go
// so this uses the user's primary group
func DropPrivTo(username string) error {

	user, err := user.Lookup(username)
	if nil != err {
		return err
	}

	uid, err := strconv.ParseInt(user.Uid, 10, 64)
	if nil != err {
		return err
	}

	gid, err := strconv.ParseInt(user.Gid, 10, 64)
	if nil != err {
		return err
	}

	err = syscall.Setgid(int(gid))
	if nil != err {
		return err
	}

	err = syscall.Setuid(int(uid))
	if nil != err {
		return err
	}

	return nil
}
