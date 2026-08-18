package localca

import "testing"

func TestVerifyPrivateSDDLRejectsBroadPrincipal(t *testing.T) {
	t.Parallel()

	err := verifyPrivateSDDL("O:S-1-5-21-42D:PAI(A;;FA;;;S-1-5-21-42)(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;WD)")
	if err == nil {
		t.Fatal("verifyPrivateSDDL() error = nil, want Everyone read rejection")
	}
}

func TestVerifyPrivateSDDLAllowsOwnerSystemAndAdministrators(t *testing.T) {
	t.Parallel()

	if err := verifyPrivateSDDL("O:S-1-5-21-42D:PAI(A;;FA;;;S-1-5-21-42)(A;;FA;;;SY)(A;;FA;;;BA)"); err != nil {
		t.Fatalf("verifyPrivateSDDL() error = %v", err)
	}
}
