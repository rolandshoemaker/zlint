// lint_san_iana_pub_suffix_empty.go

package lints

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/util"
	"strings"
	"fmt"
)

type pubSuffix struct{}

func (l *pubSuffix) Initialize() error {
	return nil
}

func (l *pubSuffix) CheckApplies(c *x509.Certificate) bool {
	return util.IsExtInCert(c, util.SubjectAlternateNameOID) && util.DNSNamesExist(c)
}

func (l *pubSuffix) Execute(c *x509.Certificate) *LintResult {
	for _, dns := range c.DNSNames {
		_, err := util.ICANNPublicSuffixParse(dns)
		if err != nil {
			if strings.HasSuffix(err.Error(), "is a suffix") {
				return &LintResult{Status: Warn}
			} else {
				return &LintResult{Status: Fatal}
			}
		}
	}
	return &LintResult{Status: Pass}
}

func init() {
	RegisterLint(&Lint{
		Name:          "w_san_iana_pub_suffix_empty",
		Description:   "The domain SHOULD NOT have a bare public suffix",
		Source:        "awslabs certlint",
		EffectiveDate: util.ZeroDate,
		Lint:          &pubSuffix{},
	})
}
