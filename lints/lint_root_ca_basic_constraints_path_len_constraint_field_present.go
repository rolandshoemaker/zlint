// lint_root_ca_basic_constraints_path_len_constraint_field_present.go
/************************************************************************************************************
7.1.2.1. Root CA Certificate
a. basicConstraints
This extension MUST appear as a critical extension. The cA field MUST be set true. The pathLenConstraint field SHOULD NOT be present.
***********************************************************************************************************/

package lints

import (
	"encoding/asn1"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/util"
)

type rootCaPathLenPresent struct{}

func (l *rootCaPathLenPresent) Initialize() error {
	return nil
}

func (l *rootCaPathLenPresent) CheckApplies(c *x509.Certificate) bool {
	return util.IsRootCA(c) && util.IsExtInCert(c, util.BasicConstOID)
}

func (l *rootCaPathLenPresent) Execute(c *x509.Certificate) *LintResult {
	bc := util.GetExtFromCert(c, util.BasicConstOID)
	var seq asn1.RawValue
	var isCa bool
	_, err := asn1.Unmarshal(bc.Value, &seq)
	if err != nil {
		return &LintResult{Status: Fatal}
	}
	if len(seq.Bytes) == 0 {
		return &LintResult{Status: Pass}
	}
	rest, err := asn1.Unmarshal(seq.Bytes, &isCa)
	if err != nil {
		return &LintResult{Status: Fatal}
	}
	if len(rest) > 0 {
		return &LintResult{Status: Warn}
	}
	return &LintResult{Status: Pass}
}

func init() {
	RegisterLint(&Lint{
		Name:          "w_root_ca_basic_constraints_path_len_constraint_field_present",
		Description:   "Root CA certificate basicConstraint extension pathLenConstraint field SHOULD NOT be present",
		Source:        "BRs: 7.1.2.1",
		EffectiveDate: util.CABEffectiveDate,
		Lint:          &rootCaPathLenPresent{},
	})
}
