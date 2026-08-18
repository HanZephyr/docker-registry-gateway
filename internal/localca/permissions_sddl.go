package localca

import (
	"errors"
	"fmt"
	"strings"
)

// verifyPrivateSDDL accepts only the owner, Local System, and local
// Administrators as principals with access to CA material. The conversion from
// a Windows security descriptor happens in permissions_windows.go; keeping
// this parser platform-neutral makes the security decision unit-testable.
func verifyPrivateSDDL(sddl string) error {
	owner, dacl, err := splitSDDL(strings.TrimSpace(sddl))
	if err != nil {
		return err
	}
	for _, ace := range sddlACEs(dacl) {
		parts := strings.Split(ace, ";")
		if len(parts) < 6 || !isAllowACE(parts[0]) || !grantsAccess(parts[2]) {
			continue
		}
		principal := strings.TrimSpace(parts[5])
		if allowedPrivatePrincipal(principal, owner) {
			continue
		}
		return fmt.Errorf("Windows ACL grants local CA material access to %q", principal)
	}
	return nil
}

func splitSDDL(value string) (string, string, error) {
	ownerStart := strings.Index(value, "O:")
	daclStart := strings.Index(value, "D:")
	if ownerStart < 0 || daclStart < 0 || ownerStart > daclStart {
		return "", "", errors.New("Windows ACL is missing owner or DACL")
	}
	owner := value[ownerStart+2 : daclStart]
	if group := strings.Index(owner, "G:"); group >= 0 {
		owner = owner[:group]
	}
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return "", "", errors.New("Windows ACL owner is empty")
	}
	dacl := value[daclStart+2:]
	if sacl := strings.Index(dacl, "S:"); sacl >= 0 {
		dacl = dacl[:sacl]
	}
	if strings.TrimSpace(dacl) == "" || strings.EqualFold(strings.TrimSpace(dacl), "NO_ACCESS_CONTROL") {
		return "", "", errors.New("Windows ACL has no restrictive DACL")
	}
	return owner, dacl, nil
}

func sddlACEs(dacl string) []string {
	var result []string
	for remaining := dacl; ; {
		start := strings.IndexByte(remaining, '(')
		if start < 0 {
			return result
		}
		remaining = remaining[start+1:]
		end := strings.IndexByte(remaining, ')')
		if end < 0 {
			return result
		}
		result = append(result, remaining[:end])
		remaining = remaining[end+1:]
	}
}

func isAllowACE(kind string) bool {
	kind = strings.ToUpper(strings.TrimSpace(kind))
	return kind == "A" || kind == "OA"
}

func grantsAccess(mask string) bool {
	mask = strings.TrimSpace(strings.ToUpper(mask))
	return mask != "" && mask != "0"
}

func allowedPrivatePrincipal(principal, owner string) bool {
	principal = strings.ToUpper(strings.TrimSpace(principal))
	owner = strings.ToUpper(strings.TrimSpace(owner))
	return principal == owner || principal == "OW" || principal == "SY" || principal == "BA"
}
