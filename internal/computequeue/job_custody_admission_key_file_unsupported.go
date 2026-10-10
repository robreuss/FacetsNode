//go:build !unix

package computequeue

func LoadJobCustodyP256AdmissionVerifier(string) (*JobCustodyP256AdmissionVerifier, error) {
	return nil, ErrJobCustodyAdmissionAuthentication
}
