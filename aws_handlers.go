package main

import (
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/gin-gonic/gin"
	"net/http"
	"os"
)

//-----------------------------------------------------------------------------

func (a *App) ListAllStandardUsers(c *gin.Context) {

	a.Log.Debug().Msg("-=- ListAllStandardUsers")
	ctx := c.Request.Context()
	users, err := a.AWS.ListAllUsers(ctx)
	if err != nil {
		a.Log.Info().Msgf("Error listing AWS users [%s]", err.Error())
		if os.Getenv("ENVIRONMENT") == "DEV" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"message": "oopsy"})
		return
	}

	var ousers []types.User
	for _, user := range users {
		if *user.Path == "/poptape-standard-users/" {
			ousers = append(ousers, user)
		}
	}

	nu := len(ousers)
	c.JSON(http.StatusOK, gin.H{"no_of_standard_users": nu, "user_details": ousers})
}
