package query

import "strings"

// Token represents a lexical token.
type Token int

const (
	// Special tokens
	ILLEGAL Token = iota
	EOF
	WS
	COLON

	// Search terms
	STRING // search fields terms

	keyword_beg

	// Boolean operators
	AND
	OR
	NOT

	keyword_end

	LPAREN // (
	RPAREN // )

)

var tokens = [...]string{
	ILLEGAL: "ILLEGAL",
	EOF:     "EOF",
	WS:      "WS",
	COLON:   ":",

	AND: "AND",
	OR:  "OR",
	NOT: "NOT",

	LPAREN: "(",
	RPAREN: ")",
}

var keywords map[string]Token

func init() {
	keywords = make(map[string]Token)
	for tok := keyword_beg + 1; tok < keyword_end; tok++ {
		keywords[strings.ToLower(tokens[tok])] = tok
	}
	for _, tok := range []Token{AND, OR} {
		keywords[strings.ToLower(tokens[tok])] = tok
	}
}

func (t Token) isOperator() bool {
	return t == AND || t == OR || t == NOT
}

// String returns the string representation of the token.
func (tok Token) String() string {
	if tok >= 0 && tok < Token(len(tokens)) {
		return tokens[tok]
	}
	return ""
}

// Precedence returns the operator precedence of the binary operator token.
func (tok Token) Precedence() int {
	switch tok {
	case OR:
		return 1
	case AND:
		return 2
	case NOT:
		return 3
	}
	return 0
}

// Lookup returns the token associated with a given string.
func Lookup(ident string) (Token, bool) {
	if tok, ok := keywords[strings.ToLower(ident)]; ok {
		return tok, true
	}
	return ILLEGAL, false
}

// tokstr returns a literal if provided, otherwise returns the token string.
func tokstr(tok Token, lit string) string {
	if lit != "" {
		return lit
	}
	return tok.String()
}
