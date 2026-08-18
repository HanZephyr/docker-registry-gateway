package trust

import (
	"os/exec"
	"strings"
)

func diagnoseWindowsTrust(options Options, contents []byte) (Diagnosis, error) {
	thumbprint, err := rootSHA1(contents)
	if err != nil {
		return Diagnosis{}, err
	}
	runner := options.CommandRunner
	if runner == nil {
		runner = func(name string, arguments ...string) ([]byte, error) {
			return exec.Command(name, arguments...).CombinedOutput()
		}
	}
	if _, err := runner("certutil", "-user", "-verifystore", "Root", thumbprint); err != nil {
		return Diagnosis{Checked: true, Details: "Windows 当前用户根证书库中未找到 DRG 根证书"}, nil
	}
	return Diagnosis{Checked: true, Trusted: true, Details: "Windows 当前用户根证书库包含 DRG 根证书"}, nil
}

func diagnoseMacOSTrust(options Options, contents []byte) (Diagnosis, error) {
	thumbprint, err := rootSHA1(contents)
	if err != nil {
		return Diagnosis{}, err
	}
	runner := options.CommandRunner
	if runner == nil {
		runner = func(name string, arguments ...string) ([]byte, error) {
			return exec.Command(name, arguments...).CombinedOutput()
		}
	}
	output, err := runner("security", "find-certificate", "-a", "-Z", "-k", "/Library/Keychains/System.keychain")
	if err != nil || !strings.Contains(strings.ToUpper(string(output)), thumbprint) {
		return Diagnosis{Checked: true, Details: "macOS 系统钥匙串中未找到 DRG 根证书"}, nil
	}
	return Diagnosis{Checked: true, Trusted: true, Details: "macOS 系统钥匙串包含 DRG 根证书"}, nil
}
