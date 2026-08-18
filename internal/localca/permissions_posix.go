//go:build !windows

package localca

import (
	"errors"
	"os"
)

// VerifyPrivateKeyPermissions rejects a local CA or server key readable by a
// group or another user on POSIX filesystems.
func VerifyPrivateKeyPermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("local CA private key permissions allow group or other access")
	}
	return nil
}

func verifyPrivateDataDirectory(string) error { return nil }

func preparePrivateDataDirectory(string) error { return nil }
