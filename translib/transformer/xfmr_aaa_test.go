package transformer

import (
	"testing"
)

func TestAaaMethodListToLoginString(t *testing.T) {
	tests := []struct {
		name     string
		input    []interface{}
		expected string
	}{
		{
			name:     "single method",
			input:    []interface{}{"tacacs+"},
			expected: "tacacs+",
		},
		{
			name:     "multiple methods",
			input:    []interface{}{"tacacs+", "local"},
			expected: "tacacs+,local",
		},
		{
			name:     "three methods",
			input:    []interface{}{"tacacs+", "local", "radius"},
			expected: "tacacs+,local,radius",
		},
		{
			name:     "empty list",
			input:    []interface{}{},
			expected: "",
		},
		{
			name:     "methods with spaces",
			input:    []interface{}{" tacacs+ ", " local "},
			expected: "tacacs+,local",
		},
		{
			name:     "filter empty strings",
			input:    []interface{}{"tacacs+", "", "local"},
			expected: "tacacs+,local",
		},
		{
			name:     "single local",
			input:    []interface{}{"local"},
			expected: "local",
		},
		{
			name:     "all supported methods",
			input:    []interface{}{"ldap", "tacacs+", "local", "radius", "default"},
			expected: "ldap,tacacs+,local,radius,default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := aaaMethodListToLoginString(tt.input)
			if result != tt.expected {
				t.Errorf("aaaMethodListToLoginString(%v) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestAaaLoginStringToMethodList(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "single method",
			input:    "tacacs+",
			expected: []string{"tacacs+"},
		},
		{
			name:     "multiple methods",
			input:    "tacacs+,local",
			expected: []string{"tacacs+", "local"},
		},
		{
			name:     "three methods",
			input:    "tacacs+,local,radius",
			expected: []string{"tacacs+", "local", "radius"},
		},
		{
			name:     "empty string",
			input:    "",
			expected: nil,
		},
		{
			name:     "methods with spaces",
			input:    " tacacs+ , local ",
			expected: []string{"tacacs+", "local"},
		},
		{
			name:     "single local",
			input:    "local",
			expected: []string{"local"},
		},
		{
			name:     "all methods",
			input:    "ldap,tacacs+,local,radius,default",
			expected: []string{"ldap", "tacacs+", "local", "radius", "default"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := aaaLoginStringToMethodList(tt.input)
			if tt.expected == nil {
				if result != nil {
					t.Errorf("aaaLoginStringToMethodList(%q) = %v, want nil", tt.input, result)
				}
				return
			}
			if len(result) != len(tt.expected) {
				t.Errorf("aaaLoginStringToMethodList(%q) returned %d items, want %d", tt.input, len(result), len(tt.expected))
				return
			}
			for i, v := range result {
				if v != tt.expected[i] {
					t.Errorf("aaaLoginStringToMethodList(%q)[%d] = %q, want %q", tt.input, i, v, tt.expected[i])
				}
			}
		})
	}
}

func TestAaaMethodListRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		methods []interface{}
	}{
		{
			name:    "tacacs+ and local",
			methods: []interface{}{"tacacs+", "local"},
		},
		{
			name:    "single method",
			methods: []interface{}{"local"},
		},
		{
			name:    "all methods",
			methods: []interface{}{"ldap", "tacacs+", "local", "radius"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loginStr := aaaMethodListToLoginString(tt.methods)
			result := aaaLoginStringToMethodList(loginStr)

			if len(result) != len(tt.methods) {
				t.Errorf("Round trip failed: input %v -> %q -> %v", tt.methods, loginStr, result)
				return
			}
			for i, v := range result {
				expected := tt.methods[i].(string)
				if v != expected {
					t.Errorf("Round trip mismatch at index %d: got %q, want %q", i, v, expected)
				}
			}
		})
	}
}
