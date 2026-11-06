package mylego

import (
	"crypto/x509"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/go-acme/lego/v5/certcrypto"
)

func (l *LegoCMD) Renew() (bool, error) {
	domain := l.C.CertDomain
	certsStorage := NewCertificatesStorage(l.path)
	// load the cert resource from files.
	// We store the certificate, private key and metadata in different files
	// as web servers would not be able to work with a combined file.
	certificates, err := certsStorage.ReadCertificate(domain, ".crt")
	if err != nil {
		log.Panicf("Error while loading the certificate for domain %s\n\t%v", domain, err)
	}

	cert := certificates[0]

	// 先判断是否到期再建 ACME 客户端：不需要续期时不访问 CA，也不要求 DNS 服务商配置齐全
	if !needRenewal(cert, domain, 30) {
		return false, nil
	}

	account, client := setup(NewAccountsStorage(l))
	setupChallenges(l, client)

	if account.Registration == nil {
		log.Panicf("Account %s is not registered. Use 'run' to register a new account.\n", account.Email)
	}

	// This is just meant to be informal for the user.
	timeLeft := cert.NotAfter.Sub(time.Now().UTC())
	log.Printf("[%s] acme: Trying renewal with %d hours remaining", domain, int(timeLeft.Hours()))

	certDomains := certcrypto.ExtractDomains(cert)

	certRes, err := obtainCertificate(certDomains, client)
	if err != nil {
		log.Panic(err)
	}

	certsStorage.SaveResource(certRes)

	return true, nil
}

func needRenewal(x509Cert *x509.Certificate, domain string, days int) bool {
	if x509Cert.IsCA {
		log.Panicf("[%s] Certificate bundle starts with a CA certificate", domain)
	}

	if days >= 0 {
		notAfter := int(time.Until(x509Cert.NotAfter).Hours() / 24.0)
		if notAfter > days {
			log.Printf("[%s] The certificate expires in %d days, the number of days defined to perform the renewal is %d: no renewal.",
				domain, notAfter, days)
			return false
		}
	}

	return true
}
