//go:build windows

package gjl

import "golang.org/x/sys/windows"

func ProfileAddress(development bool) (string, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	suffix := "-daemon-v1"
	if development {
		suffix = "-development-daemon-v1"
	}
	return `\\.\pipe\gjl-` + user.User.Sid.String() + suffix, nil
}
