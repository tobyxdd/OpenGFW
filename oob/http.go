package oob

type HTTPInspector struct {
	Policies []HTTPPolicy
}

type HTTPPolicy struct {
	Name   string
	Domain string
	Method string // empty = all methods
	Path   string // empty = all paths
}
