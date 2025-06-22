package main

import (
	"errors"
	poptapeUtils "github.com/cliveyg/poptape-admin/utils"
	"github.com/google/uuid"
	"gorm.io/gorm/utils"
	"os"
	"time"
)

func (a *App) CreateFirstUser() error {

	fu, fuExists := os.LookupEnv("FIRSTUSER")
	pw, pwExists := os.LookupEnv("FIRSTPASS")
	if !fuExists || !pwExists {
		return errors.New("first user env vars not present in .env")
	}
	encryptedPW, err := poptapeUtils.GenerateHashPassword(pw)
	if err != nil {
		return errors.New("unable to encrypt password")
	}

	u := &Users{
		AdminId:   uuid.UUID{},
		Username:  fu,
		Password:  encryptedPW,
		LastLogin: time.Now(),
		Active:    true,
		Validated: false,
		Created:   time.Now(),
	}
	a.Log.Debug().Msgf("User is %s", utils.ToString(u))
	a.DB.Create(u)

	return nil
}
