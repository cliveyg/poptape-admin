package main

import (
	"errors"
	"github.com/cliveyg/poptape-admin/utils"
)

func (a *App) checkLoginDetails(l *Login, u *User) error {

	res := a.DB.First(&u)
	if res.Error != nil {
		a.Log.Info().Msgf("Login attempted with user [%s]", l.Username)
		a.Log.Error().Msgf("Error: [%s]", res.Error)
		return res.Error
	}
	if !u.Validated {
		a.Log.Info().Msgf("User [%s]: not validated", u.Username)
		return errors.New("user not validated")
	}

	if !utils.VerifyPassword(l.Password, u.Password) {
		a.Log.Info().Msgf("User [%s]: password incorrect", u.Username)
		return errors.New("password doesn't match")
	}

	return nil
}
