package lldap

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

type LDAPConfig struct {
	// ldap://lldap:3890 或 ldaps://lldap:6360
	URL string

	// dc=example,dc=com
	BaseDN string

	// uid=admin,ou=people,dc=example,dc=com
	BindDN       string
	BindPassword string

	TLSConfig *tls.Config
	StartTLS  bool
	Timeout   time.Duration
}

type LDAPClient struct {
	cfg LDAPConfig
}

func NewLDAPClient(cfg LDAPConfig) (*LDAPClient, error) {
	if cfg.URL == "" {
		return nil, errors.New("lldap: ldap url is required")
	}
	if cfg.BaseDN == "" {
		return nil, errors.New("lldap: ldap base dn is required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	return &LDAPClient{cfg: cfg}, nil
}

var dnEscaper = strings.NewReplacer(
	`\`, `\\`,
	`,`, `\,`,
	`+`, `\+`,
	`"`, `\"`,
	`<`, `\<`,
	`>`, `\>`,
	`;`, `\;`,
	`=`, `\=`,
)

func (l *LDAPClient) UserDN(userID string) string {
	return "uid=" + dnEscaper.Replace(userID) +
		",ou=people," + l.cfg.BaseDN
}

func (l *LDAPClient) dial(ctx context.Context) (*ldap.Conn, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	u, err := url.Parse(l.cfg.URL)
	if err != nil {
		return nil, fmt.Errorf(
			"lldap: parse ldap url %q: %w",
			l.cfg.URL,
			err,
		)
	}
	if u.Host == "" {
		return nil, fmt.Errorf(
			"lldap: ldap url %q has no host",
			l.cfg.URL,
		)
	}

	dialTimeout := l.cfg.Timeout
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining < dialTimeout {
			dialTimeout = remaining
		}
	}
	if dialTimeout <= 0 {
		return nil, context.DeadlineExceeded
	}

	opts := []ldap.DialOpt{
		ldap.DialWithDialer(&net.Dialer{Timeout: dialTimeout}),
	}

	switch strings.ToLower(u.Scheme) {
	case "ldap":
		// plain connection; StartTLS is handled below.
	case "ldaps":
		opts = append(
			opts,
			ldap.DialWithTLSConfig(l.tlsConfig(u.Hostname())),
		)
	default:
		return nil, fmt.Errorf(
			"lldap: unsupported ldap scheme %q",
			u.Scheme,
		)
	}

	conn, err := ldap.DialURL(l.cfg.URL, opts...)
	if err != nil {
		return nil, fmt.Errorf(
			"lldap: dial %s: %w",
			l.cfg.URL,
			err,
		)
	}

	if l.cfg.StartTLS {
		if strings.ToLower(u.Scheme) != "ldap" {
			conn.Close()
			return nil, errors.New(
				"lldap: StartTLS requires ldap:// scheme",
			)
		}
		if err := conn.StartTLS(l.tlsConfig(u.Hostname())); err != nil {
			conn.Close()
			return nil, fmt.Errorf(
				"lldap: starttls: %w",
				err,
			)
		}
	}

	if deadline, ok := ctx.Deadline(); ok {
		timeout := time.Until(deadline)
		if timeout <= 0 {
			conn.Close()
			return nil, context.DeadlineExceeded
		}
		conn.SetTimeout(timeout)
	} else {
		conn.SetTimeout(l.cfg.Timeout)
	}
	return conn, nil
}

func (l *LDAPClient) tlsConfig(serverName string) *tls.Config {
	if l.cfg.TLSConfig == nil {
		return &tls.Config{ServerName: serverName}
	}
	cfg := l.cfg.TLSConfig.Clone()
	if cfg.ServerName == "" {
		cfg.ServerName = serverName
	}
	return cfg
}

// Authenticate 用用户 DN 直接 bind。
// 成功即用户名密码正确。
func (l *LDAPClient) Authenticate(
	ctx context.Context,
	userID string,
	password string,
) error {
	if userID == "" || password == "" {
		return ErrInvalidCredentials
	}

	conn, err := l.dial(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := conn.Bind(
		l.UserDN(userID),
		password,
	); err != nil {
		return fmt.Errorf(
			"%w: %v",
			ErrInvalidCredentials,
			err,
		)
	}
	return nil
}

// SetPassword 用管理员 bind 后发 password modify 扩展操作。
// GraphQL 不提供改密接口，这是官方推荐方式。
func (l *LDAPClient) SetPassword(
	ctx context.Context,
	userID string,
	newPassword string,
) error {
	if userID == "" || newPassword == "" {
		return errors.New(
			"lldap: user id and new password are required",
		)
	}
	if l.cfg.BindDN == "" {
		return errors.New(
			"lldap: BindDN is required to set passwords",
		)
	}

	conn, err := l.dial(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := conn.Bind(
		l.cfg.BindDN,
		l.cfg.BindPassword,
	); err != nil {
		return fmt.Errorf(
			"lldap: ldap service bind: %w",
			err,
		)
	}

	_, err = conn.PasswordModify(
		ldap.NewPasswordModifyRequest(
			l.UserDN(userID),
			"",
			newPassword,
		),
	)
	if err != nil {
		return fmt.Errorf(
			"lldap: password modify: %w",
			err,
		)
	}
	return nil
}

type LDAPUser struct {
	DN         string
	Attributes map[string][]string
}

// GetUser 通过 LDAP 读用户，
// 适合认证链路里顺便取 mail/displayName/memberOf。
func (l *LDAPClient) GetUser(
	ctx context.Context,
	userID string,
) (*LDAPUser, error) {
	conn, err := l.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if l.cfg.BindDN != "" {
		if err := conn.Bind(
			l.cfg.BindDN,
			l.cfg.BindPassword,
		); err != nil {
			return nil, fmt.Errorf(
				"lldap: ldap service bind: %w",
				err,
			)
		}
	}

	res, err := conn.Search(ldap.NewSearchRequest(
		"ou=people,"+l.cfg.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		"(uid="+ldap.EscapeFilter(userID)+")",
		[]string{"*"},
		nil,
	))
	if err != nil {
		return nil, fmt.Errorf(
			"lldap: ldap search: %w",
			err,
		)
	}
	if len(res.Entries) == 0 {
		return nil, ErrNotFound
	}

	e := res.Entries[0]
	attrs := make(
		map[string][]string,
		len(e.Attributes),
	)
	for _, a := range e.Attributes {
		attrs[a.Name] = a.Values
	}
	return &LDAPUser{
		DN:         e.DN,
		Attributes: attrs,
	}, nil
}
