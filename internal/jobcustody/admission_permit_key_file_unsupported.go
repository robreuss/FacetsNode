//go:build !unix

package jobcustody

func LoadAdmissionPermitVerifier(string) (*AdmissionPermitVerifier, error) {
	return nil, ErrAdmissionPermitAuthentication
}
