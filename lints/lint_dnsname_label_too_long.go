package lints

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/util"
	"strings"
)

type DNSNameLabelLengthTooLong struct{}

func (l *DNSNameLabelLengthTooLong) Initialize() error {
	return nil
}

func (l *DNSNameLabelLengthTooLong) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c) && util.DNSNamesExist(c)
}

func labelLengthTooLong(domain string) bool {
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if len(label) > 63 {
			return true
		}
	}
	return false
}

func (l *DNSNameLabelLengthTooLong) Execute(c *x509.Certificate) *LintResult {
	if c.Subject.CommonName != "" {
		labelTooLong := labelLengthTooLong(c.Subject.CommonName)
		if labelTooLong {
			return &LintResult{Status: Error}
		}
	}
	for _, dns := range c.DNSNames {
		labelTooLong := labelLengthTooLong(dns)
		if labelTooLong {
			return &LintResult{Status: Error}
		}
	}
	return &LintResult{Status: Pass}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_dnsname_label_too_long",
		Description:   "DNSName labels MUST be less than or equal to 63 characters",
		Source:        "RFC 1035",
		EffectiveDate: util.RFC1035Date,
		Lint:          &DNSNameLabelLengthTooLong{},
	})
}
