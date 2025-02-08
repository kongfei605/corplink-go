package main

type State string

const (
	StateInit  State = "Init"
	StateLogin State = "Login"
)

func (s State) String() string {
	return string(s)
}
