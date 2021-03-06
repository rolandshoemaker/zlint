// lint_ca_subject_field_empty.go
/************************************************
RFC 5280: 4.1.2.6
The subject field identifies the entity associated with the public
   key stored in the subject public key field.  The subject name MAY be
   carried in the subject field and/or the subjectAltName extension.  If
   the subject is a CA (e.g., the basic constraints extension, as
   discussed in Section 4.2.1.9, is present and the value of cA is
   TRUE), then the subject field MUST be populated with a non-empty
   distinguished name matching the contents of the issuer field (Section
   4.1.2.4) in all certificates issued by the subject CA.
************************************************/

package lints

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/util"
)

type caSubjectEmpty struct{}

func (l *caSubjectEmpty) Initialize() error {
	return nil
}

func (l *caSubjectEmpty) CheckApplies(c *x509.Certificate) bool {
	return c.IsCA
}

func (l *caSubjectEmpty) Execute(c *x509.Certificate) *LintResult {
	if &c.Subject != nil && util.NotAllNameFieldsAreEmpty(&c.Subject) {
		return &LintResult{Status: Pass}
	} else {
		return &LintResult{Status: Error}
	}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_ca_subject_field_empty",
		Description:   "CA Certificates subject field MUST not be empty and MUST have a non-empty distingushed name",
		Source:        "RFC 5280: 4.1.2.6",
		EffectiveDate: util.RFC2459Date,
		Lint:          &caSubjectEmpty{},
	})
}
