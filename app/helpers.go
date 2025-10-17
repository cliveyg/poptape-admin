package app

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/cliveyg/poptape-admin/utils"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/gridfs"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"gorm.io/gorm"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"
)

type YHeader struct {
	TokenString string `header:"y-access-token" binding:"required"`
}

//-----------------------------------------------------------------------------
// GetUUIDFromParams
//-----------------------------------------------------------------------------

func (a *App) GetUUIDFromParams(c *gin.Context, u *uuid.UUID, key string) error {

	var err error
	idAny, _ := c.Get(key)
	if idAny == nil {
		a.Log.Info().Msgf("Key [%s] is missing", key)
		return errors.New("key is missing")
	}
	*u, err = uuid.Parse(fmt.Sprintf("%v", idAny))
	if err != nil {
		a.Log.Info().Msgf("Input not a uuid string: [%s]", err.Error())
		return err
	}
	return nil
}

//-----------------------------------------------------------------------------
// checkLoginDetails
//-----------------------------------------------------------------------------

func (a *App) checkLoginDetails(l *Login, u *User) error {

	res := a.DB.Preload("Roles").First(&u, "username = ?", l.Username)
	if res.Error != nil {
		a.Log.Info().Msgf("Login attempted with user [%s]", l.Username)
		a.Log.Error().Msgf("Error: [%s]", res.Error)
		return res.Error
	}
	if u.Validated == false {
		a.Log.Info().Msgf("User [%s]: not validated", u.Username)
		return errors.New("user not validated")
	}
	if u.Active == false {
		a.Log.Info().Msgf("User [%s]: not active", u.Username)
		return errors.New("user not active")
	}
	pass, err := base64.StdEncoding.DecodeString(l.Password)
	if err != nil {
		a.Log.Info().Msgf("Base64 decoding failed [%s]", err.Error())
		return err
	}
	if !utils.VerifyPassword(pass, u.Password) {
		a.Log.Info().Msgf("User [%s]: password incorrect", u.Username)
		return errors.New("password doesn't match")
	}

	return nil
}

//-----------------------------------------------------------------------------
// hasValidJWT
//-----------------------------------------------------------------------------

func (a *App) hasValidJWT(c *gin.Context) bool {

	var y YHeader
	var err error
	if err = c.ShouldBindHeader(&y); err != nil {
		a.Log.Info().Msg("Missing y-access-token")
		a.Log.Debug().Msgf("Unable to bind y-access-token header [%s]", err.Error())
		return false
	}

	var claims *utils.Claims
	claims, err = utils.ParseToken(y.TokenString)
	if err != nil {
		a.Log.Info().Msgf("Failure to parse token [%s]", err.Error())
		return false
	}

	var aId uuid.UUID
	aId, err = uuid.Parse(claims.AdminId)
	if err != nil {
		a.Log.Info().Msgf("Failure to parse token; Invalid admin UUID")
		return false
	}

	u := User{Username: claims.Username, AdminId: aId}

	res := a.DB.Preload("Roles").Find(&u)
	if res.Error != nil {
		a.Log.Info().Msgf("Failed jwt validation with username [%s]", u.Username)
		a.Log.Error().Msgf("Error: [%s]", res.Error)
		return false
	}
	if u.Validated {
		c.Set("user", u)
		return true
	}
	a.Log.Info().Msgf("Failed jwt validation; user [%s] not validated", u.Username)
	return false
}

//-----------------------------------------------------------------------------
// userHasValidRole
//-----------------------------------------------------------------------------

func (a *App) userHasValidRole(roles []Role, allowedRoles []string) bool {

	rf := false
	for i := 0; i < len(roles); i++ {
		if slices.Contains(allowedRoles, roles[i].Name) {
			rf = true
			break
		}
	}
	return rf
}

//-----------------------------------------------------------------------------
// encryptCredPass
//-----------------------------------------------------------------------------

func (a *App) encryptCredPass(cr *Cred) error {
	// decode input password, encrypt it and put it back in same field
	p64, err := base64.StdEncoding.DecodeString(cr.DBPassword)
	if err != nil {
		a.Log.Info().Msgf("Base64 decoding failed [%s]", err.Error())
		return errors.New(fmt.Sprintf("Base64 decoding failed [%s]", err.Error()))
	}
	var est string
	est, err = utils.Encrypt(p64, []byte(os.Getenv("SUPERSECRETKEY")), []byte(os.Getenv("SUPERSECRETNONCE")))
	if err != nil {
		a.Log.Info().Msgf("Encryption failed [%s]", err.Error())
		return errors.New(fmt.Sprintf("Encryption failed [%s]", err.Error()))
	}
	cr.DBPassword = est
	return nil
}

//-----------------------------------------------------------------------------
// userHasCorrectAccess
//-----------------------------------------------------------------------------

func (a *App) userHasCorrectAccess(svRec *SaveRecord, u *User) (int, error) {
	rcms := RoleCredMS{
		CredId:         svRec.CredId,
		MicroserviceId: svRec.MicroserviceId,
	}
	res := a.DB.First(&rcms)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			a.Log.Info().Msgf("RoleCredMS not found [%v]", svRec)
			return http.StatusNotFound, errors.New("RoleCredMS record not found")
		}
		a.Log.Info().Msgf("Error finding RoleCredMS [%s]", res.Error.Error())
		return http.StatusInternalServerError, errors.New("Something went boooom")
	}
	validRoles := []string{"super", "admin"}
	validRoles = append(validRoles, rcms.RoleName)

	if !a.userHasValidRole(u.Roles, validRoles) {
		a.Log.Info().Msgf("User [%s] does not have valid role", u.Username)
		return http.StatusForbidden, errors.New("Forbidden")
	}
	return http.StatusOK, nil
}

//-----------------------------------------------------------------------------
// getRoleDetails
//-----------------------------------------------------------------------------

func (a *App) getRoleDetails(c *gin.Context, u *User, rName *string) error {
	if !utils.IsValidUUIDString(c.Param("aId")) {
		a.Log.Info().Msgf("Invalid aId in url [%s]", c.Param("aId"))
		return errors.New("Invalid aId in url")
	}
	adminId, _ := uuid.Parse(c.Param("aId"))

	if !utils.IsAcceptedString(c.Param("rName")) {
		a.Log.Info().Msgf("Invalid rolename in url [%s]", c.Param("rName"))
		return errors.New("Invalid rolename in url")
	}
	*rName = c.Param("rName")
	if len(*rName) > 20 {
		a.Log.Info().Msg("Role name is too long")
		return errors.New("role name is too long")
	}

	u.AdminId = adminId
	res := a.DB.Preload("Roles").Find(&u)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			a.Log.Info().Msgf("User [%s] not found", u.AdminId.String())
			return res.Error
		}
		a.Log.Info().Msgf("Error finding user [%s]", res.Error)
		return res.Error
	}

	if u.Username == "" {
		return errors.New("user not found")
	}
	return nil
}

//-----------------------------------------------------------------------------
// writeSQLOut
//-----------------------------------------------------------------------------

func (a *App) writeSQLOut(cm string, crdRec *Cred, pw *[]byte, tabRet bool) (any, error) {
	var stdoutBuf, stderrBuf bytes.Buffer

	// build psql arguments
	args := []string{
		"-h", crdRec.Host,
		"-U", crdRec.DBUsername,
		"-p", crdRec.DBPort,
		"-d", crdRec.DBName,
		"-c", cm,
	}
	if tabRet {
		args = append(args, "-A", "-t")
	}
	cmd := a.CommandRunner.Command("psql", args...)
	cmd.SetEnv(append(os.Environ(), "PGPASSWORD="+string(*pw)))
	a.Log.Debug().Msg("After CommandRunner.Command ✓")

	cmd.SetStdout(&stdoutBuf)
	cmd.SetStderr(&stderrBuf)

	err := cmd.Run()
	a.Log.Debug().Msgf("STDOUT:\n%s\n", stdoutBuf.String())
	a.Log.Debug().Msgf("STDERR:\n%s\n", stderrBuf.String())
	if err != nil {
		//fmt.Printf("psql command failed: %v\n", err)
		a.Log.Info().Msgf("psql command failed: %s", err.Error())
		a.Log.Info().Msgf("STDERR:\n%s\n", stderrBuf.String())
		return nil, err
	}

	return stdoutBuf.String(), nil
}

//-----------------------------------------------------------------------------
// writeMongoOut
//-----------------------------------------------------------------------------

func (a *App) writeMongoOut(c *gin.Context, cmdStr string, crdRec *Cred, pw *[]byte) (string, error) {
	var stdoutBuf, stderrBuf bytes.Buffer

	uri := fmt.Sprintf("mongodb://%s:%s@%s:%s/%s?authSource=%s",
		crdRec.DBUsername, string(*pw), crdRec.Host, crdRec.DBPort, crdRec.DBName, crdRec.DBName)

	a.Log.Debug().Msgf("mongo driver URI is <<%s>>", uri)
	a.Log.Debug().Msgf("writeMongoOut cmdStr is <<%s>>", cmdStr)

	// Use the gin.Context's request context for Mongo operations
	mongoCtx := c.Request.Context()

	client, err := mongo.Connect(mongoCtx, options.Client().ApplyURI(uri))
	if err != nil {
		a.Log.Info().Msgf("mongo client connect failed: %s", err.Error())
		return "", err
	}
	defer func() { _ = client.Disconnect(mongoCtx) }()

	if err := client.Ping(mongoCtx, readpref.Primary()); err != nil {
		a.Log.Info().Msgf("mongo ping failed: %s", err.Error())
		return "", err
	}

	// Handle "drop all collections" pattern
	if strings.HasPrefix(cmdStr, "db.getCollectionNames().forEach") {
		collNames, err := client.Database(crdRec.DBName).ListCollectionNames(mongoCtx, map[string]interface{}{})
		if err != nil {
			a.Log.Info().Msgf("Failed to list collections: %s", err.Error())
			return "", err
		}
		var dropped int64
		for _, name := range collNames {
			err := client.Database(crdRec.DBName).Collection(name).Drop(mongoCtx)
			if err != nil {
				a.Log.Info().Msgf("Failed to drop collection %s: %s", name, err.Error())
				stderrBuf.WriteString(fmt.Sprintf("Failed to drop %s: %v\n", name, err))
			} else {
				dropped++
				stdoutBuf.WriteString(fmt.Sprintf("Dropped collection: %s\n", name))
			}
		}
		stdoutBuf.WriteString(fmt.Sprintf("Dropped %d collections\n", dropped))
		return stdoutBuf.String(), nil
	}

	// Handle "db.collection.deleteMany({})" pattern
	var collectionName string
	cmdStr = strings.TrimSpace(cmdStr)
	if strings.HasPrefix(cmdStr, "db.") && strings.Contains(cmdStr, ".deleteMany") {
		s := strings.TrimPrefix(cmdStr, "db.")
		collectionName = strings.SplitN(s, ".", 2)[0]
		a.Log.Debug().Msgf("Deleting all documents in collection: %s", collectionName)
		coll := client.Database(crdRec.DBName).Collection(collectionName)
		result, err := coll.DeleteMany(mongoCtx, map[string]interface{}{})
		if err != nil {
			a.Log.Info().Msgf("collection deleteMany failed: %s", err.Error())
			return "", err
		}
		stdoutBuf.WriteString(fmt.Sprintf("Deleted %d documents from collection %s\n", result.DeletedCount, collectionName))
		return stdoutBuf.String(), nil
	}

	// Unknown or unsupported command pattern
	stderrBuf.WriteString("Could not parse or execute cmdStr: " + cmdStr)
	a.Log.Info().Msg(stderrBuf.String())
	return "", errors.New(stderrBuf.String())
}

//-----------------------------------------------------------------------------
// listTables
//-----------------------------------------------------------------------------

func (a *App) listTables(crd *Cred, pw *[]byte) ([]string, error) {

	var tables []string
	cm := "SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname NOT IN ('pg_catalog', 'information_schema');"
	out, err := a.writeSQLOut(cm, crd, pw, true)
	if err != nil {
		return nil, err
	}

	s, ok := out.(string)
	if !ok {
		return nil, errors.New("unable to cast any to string")
	}

	tables = strings.Split(strings.TrimSpace(s), "\n")
	a.Log.Info().Msgf("output is [%s]", tables)

	return tables, nil
}

//-----------------------------------------------------------------------------
// SaveWithAutoVersion
//-----------------------------------------------------------------------------

func (a *App) SaveWithAutoVersion(rec *SaveRecord) error {
	const maxAttempts = 5
	for attempt := 0; attempt < maxAttempts; attempt++ {
		err := a.DB.Transaction(func(tx *gorm.DB) error {
			var maxVersion int
			err := tx.Model(&SaveRecord{}).
				Where("microservice_id = ?", rec.MicroserviceId).
				Select("COALESCE(MAX(version), 0)").Scan(&maxVersion).Error
			if err != nil {
				return err
			}
			rec.Version = maxVersion + 1
			return tx.Create(rec).Error
		})
		if err == nil {
			return nil
		}
		if strings.Contains(err.Error(), "duplicate key value violates unique constraint") {
			time.Sleep(10 * time.Millisecond)
			continue // retry
		}
		return err
	}
	return fmt.Errorf("failed to insert SaveRecord for microservice %s after max attempts", rec.MicroserviceId.String())
}

//-----------------------------------------------------------------------------
// decryptPassword
//-----------------------------------------------------------------------------

func (a *App) decryptPassword(encPw string) ([]byte, error) {
	key := []byte(os.Getenv("SUPERSECRETKEY"))
	nonce := []byte(os.Getenv("SUPERSECRETNONCE"))
	pw, err := utils.Decrypt(encPw, key, nonce)
	if err != nil {
		a.Log.Info().Msgf("Error decrypting password from creds [%s]", err.Error())
		return nil, err
	}
	a.Log.Debug().Msg("Successfully decrypted password ✓")
	return pw, nil
}

//-----------------------------------------------------------------------------
// setupAndStartCmd
//-----------------------------------------------------------------------------

func (a *App) setupAndStartCmd(name string, args []string, env []string, logPrefix string) (Cmd, io.ReadCloser, error) {
	cmd := a.CommandRunner.Command(name, args...)
	if env != nil {
		cmd.SetEnv(append(os.Environ(), env...))
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		a.Log.Info().Msgf("Error from StdoutPipe [%s]", err.Error())
		return nil, nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		a.Log.Info().Msgf("Error from StderrPipe [%s]", err.Error())
		return nil, nil, err
	}
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			a.Log.Info().Msgf("[%s stderr] %s", logPrefix, scanner.Text())
		}
	}()
	if err = cmd.Start(); err != nil {
		a.Log.Info().Msgf("Error starting %s [%s]", logPrefix, err.Error())
		return nil, nil, err
	}
	a.Log.Debug().Msgf("Successfully started %s ✓", logPrefix)
	return cmd, stdout, nil
}

//-----------------------------------------------------------------------------
// createGridFSUploadStream - GridFS bucket and upload stream creation
//-----------------------------------------------------------------------------

func (a *App) createGridFSUploadStream(db, filename string, metadata map[string]interface{}) (*gridfs.UploadStream, error) {
	mdb := a.Mongo.Database(db)
	bucket, err := gridfs.NewBucket(mdb)
	if err != nil {
		a.Log.Info().Msgf("Error creating GridFS bucket [%s]", err.Error())
		return nil, err
	}
	a.Log.Debug().Msg("Successfully created bucket ✓")
	uploadStream, err := bucket.OpenUploadStream(filename, options.GridFSUpload().SetMetadata(metadata))
	if err != nil {
		a.Log.Info().Msgf("Error opening upload stream [%s]", err.Error())
		return nil, err
	}
	a.Log.Debug().Msg("Successfully opened upload stream ✓")
	return uploadStream, nil
}

//-----------------------------------------------------------------------------
// copyToGridFS - copy stream and log errors
//-----------------------------------------------------------------------------

func (a *App) copyToGridFS(uploadStream *gridfs.UploadStream, stdout io.Reader, logPrefix string) (int64, error) {
	n, err := io.Copy(uploadStream, stdout)
	if err != nil {
		a.Log.Info().Msgf("Error copying data to uploadStream [%s]", err.Error())
		return n, err
	}
	a.Log.Debug().Msgf("Copied %d bytes to GridFS for %s", n, logPrefix)
	return n, nil
}
