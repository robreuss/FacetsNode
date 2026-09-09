package main

// Delivered only in an explicit authenticated management request, never health
// or diagnostic exports. Setup code is a separate explicit response field.
type managementDetails struct {
	Onion           string `json:"onion"`
	CertificateDER  []byte `json:"certificateDER"`
	SPKISHA256      string `json:"spkiSHA256"`
	ServiceIdentity string `json:"serviceIdentity"`
	BoxID           string `json:"boxID"`
	SetupRequired   bool   `json:"setupRequired"`
}
