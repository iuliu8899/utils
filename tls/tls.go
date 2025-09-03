package tls

import (
	"crypto/tls"
	"github.com/samber/lo"
)

type Option func(*tls.Config)

func NewTlsConfig(options ...Option) *tls.Config {
	ret := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionSSL30,
		MaxVersion:         tls.VersionTLS13,
		Renegotiation:      tls.RenegotiateOnceAsClient,
	}
	for _, option := range options {
		option(ret)
	}
	return ret
}

func WithAllCiphers() Option {
	return func(config *tls.Config) {
		config.CipherSuites = lo.Map(append(tls.CipherSuites(), tls.InsecureCipherSuites()...), func(item *tls.CipherSuite, index int) uint16 {
			return item.ID
		})
	}
}
