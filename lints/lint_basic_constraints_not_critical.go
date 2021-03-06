/*
 * ZLint Copyright 2017 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package lints

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/util"
)

/************************************************
RFC 5280: 4.2.1.9
Conforming CAs MUST include this extension in all CA certificates that contain
public keys used to validate digital signatures on certificates and MUST mark
the extension as critical in such certificates.  This extension MAY appear as a
critical or non- critical extension in CA certificates that contain public keys
used exclusively for purposes other than validating digital signatures on
certificates.  Such CA certificates include ones that contain public keys used
exclusively for validating digital signatures on CRLs and ones that contain key
management public keys used with certificate.
************************************************/

type basicConstCrit struct{}

func (l *basicConstCrit) Initialize() error {
	return nil
}

func (l *basicConstCrit) CheckApplies(c *x509.Certificate) bool {
	return c.IsCA && util.IsExtInCert(c, util.BasicConstOID)
}

func (l *basicConstCrit) Execute(c *x509.Certificate) *LintResult {
	// Add actual lint here
	if e := util.GetExtFromCert(c, util.BasicConstOID); e != nil {
		if e.Critical {
			return &LintResult{Status: Pass}
		} else {
			return &LintResult{Status: Error}
		}
	} else {
		return &LintResult{Status: NA}
	}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_basic_constraints_not_critical",
		Description:   "basicConstraints MUST appear as a critical extension",
		Source:        "RFC 5280: 4.2.1.9",
		EffectiveDate: util.RFC2459Date,
		Lint:          &basicConstCrit{},
	})
}
