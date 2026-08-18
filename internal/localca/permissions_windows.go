//go:build windows

package localca

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

const (
	ownerSecurityInformation = 0x00000001
	daclSecurityInformation  = 0x00000004
	securityDescriptorRev1   = 1
)

var (
	advapi32DLL                                          = syscall.NewLazyDLL("advapi32.dll")
	getNamedSecurityInfoW                                = advapi32DLL.NewProc("GetNamedSecurityInfoW")
	convertSecurityDescriptorToStringSecurityDescriptorW = advapi32DLL.NewProc("ConvertSecurityDescriptorToStringSecurityDescriptorW")
)

// VerifyPrivateKeyPermissions checks both the key and its containing PKI
// directory. Windows file mode bits do not model effective ACLs, so failure to
// inspect the descriptor is treated as unsafe rather than silently accepted.
func VerifyPrivateKeyPermissions(path string) error {
	if err := verifyWindowsPrivatePath(path); err != nil {
		return fmt.Errorf("verify local CA private key ACL: %w", err)
	}
	return verifyWindowsPrivatePath(filepath.Dir(path))
}

func verifyPrivateDataDirectory(path string) error {
	if err := verifyWindowsPrivatePath(path); err != nil {
		return fmt.Errorf("verify local CA data directory ACL: %w", err)
	}
	return nil
}

// preparePrivateDataDirectory removes inherited ACL entries before the first
// CA key is created. Existing directories are never silently rewritten: a
// later reconciliation verifies and refuses an unsafe directory instead.
func preparePrivateDataDirectory(path string) error {
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return fmt.Errorf("open current Windows token: %w", err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return fmt.Errorf("read current Windows token user: %w", err)
	}
	owner, err := user.User.Sid.String()
	if err != nil {
		return fmt.Errorf("render current Windows user SID: %w", err)
	}
	arguments := []string{
		path,
		"/inheritance:r",
		"/grant:r", "*" + owner + ":(OI)(CI)F",
		"/grant:r", "*S-1-5-18:(OI)(CI)F",
		"/grant:r", "*S-1-5-32-544:(OI)(CI)F",
	}
	if output, err := exec.Command("icacls", arguments...).CombinedOutput(); err != nil {
		return fmt.Errorf("harden Windows PKI directory ACL: %w (%s)", err, strings.TrimSpace(string(output)))
	}
	return verifyPrivateDataDirectory(path)
}

func verifyWindowsPrivatePath(path string) error {
	sddl, err := windowsSecurityDescriptor(path)
	if err != nil {
		return err
	}
	return verifyPrivateSDDL(sddl)
}

func windowsSecurityDescriptor(path string) (string, error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	var descriptor uintptr
	status, _, _ := getNamedSecurityInfoW.Call(
		uintptr(unsafe.Pointer(name)),
		1, // SE_FILE_OBJECT
		ownerSecurityInformation|daclSecurityInformation,
		0, 0, 0, 0,
		uintptr(unsafe.Pointer(&descriptor)),
	)
	if status != 0 {
		return "", syscall.Errno(status)
	}
	defer syscall.LocalFree(syscall.Handle(descriptor))

	var rendered *uint16
	var length uint32
	ok, _, callErr := convertSecurityDescriptorToStringSecurityDescriptorW.Call(
		descriptor,
		securityDescriptorRev1,
		ownerSecurityInformation|daclSecurityInformation,
		uintptr(unsafe.Pointer(&rendered)),
		uintptr(unsafe.Pointer(&length)),
	)
	if ok == 0 {
		return "", callErr
	}
	defer syscall.LocalFree(syscall.Handle(unsafe.Pointer(rendered)))
	return syscall.UTF16ToString(unsafe.Slice(rendered, int(length))), nil
}
