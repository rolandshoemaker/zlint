package util

import (
	"github.com/asaskevich/govalidator"
	"net"
	"strings"
)

func removeQuestionMarks(domain string) string {
	hasQuestionMarkPrefix := strings.HasPrefix(domain, "?.")
	for hasQuestionMarkPrefix == true {
		domain = domain[2:]
		hasQuestionMarkPrefix = strings.HasPrefix(domain, "?.")
	}
	return domain
}

func IsFQDN(domain string) bool {
	domain = removeQuestionMarks(domain)
	if strings.HasPrefix(domain, "*.") {
		domain = domain[2:]
	}
	if strings.Contains(domain, "://") {
		return false
	}
	if strings.Contains(domain, "/") {
		return false
	}
	if strings.Contains(domain, ":") {
		return false
	}
	if strings.Contains(domain, "@") {
		return false
	}
	dnsNameValidator := govalidator.IsDNSName(domain)
	urlValidator := govalidator.IsURL(domain)
	return dnsNameValidator || urlValidator
}

func GetAuthority(uri string) string {
	if len(uri) < 4 {
		return ""
	}
	idx := strings.Index(uri, "//")
	for i := idx + 2; i < len(uri); i++ {
		if uri[i] == '/' || uri[i] == '#' || uri[i] == '?' {
			return uri[idx+2 : i]
		}
	}
	if idx != -1 {
		return uri[idx+2:]
	}
	return ""
}

func GetHost(auth string) string {
	begin := strings.Index(auth, "@")
	if begin == -1 || begin == len(auth)-1 {
		return ""
	}
	end := strings.Index(auth, ":")
	if end == -1 {
		end = len(auth)
	}
	if end < begin {
		return ""
	}
	return auth[begin+1 : end]
}

func AuthIsFQDNOrIP(auth string) bool {
	if IsFQDN(auth) {
		return true
	}
	if net.ParseIP(auth) != nil {
		return true
	}
	return false
}
