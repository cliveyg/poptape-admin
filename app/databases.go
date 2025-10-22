package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/cliveyg/poptape-admin/utils"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"io"
	"net/http"
	"os"
	"slices"
	"time"
)

//-----------------------------------------------------------------------------
// InitialiseMongo
//-----------------------------------------------------------------------------

func (a *App) InitialiseMongo() {

	timeout := 60 * time.Second
	start := time.Now()
	var err error
	var client *mongo.Client
	x := 1

	mongoHost := os.Getenv("MONGO_HOST")
	mongoPort := os.Getenv("MONGO_PORT")
	mongoDB := os.Getenv("MONGO_DBNAME")
	mongoUser := os.Getenv("MONGO_USERNAME")
	mongoPass := os.Getenv("MONGO_PASSWORD")

	// Build MongoDB URI
	mongoURI := fmt.Sprintf("mongodb://%s:%s@%s:%s/%s?authSource=admin",
		mongoUser, mongoPass, mongoHost, mongoPort, mongoDB,
	)

	for time.Since(start) < timeout {
		a.Log.Debug().Msgf("Trying to connect to MongoDB...[%d]", x)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		clientOptions := options.Client().ApplyURI(mongoURI)
		client, err = mongo.Connect(ctx, clientOptions)
		if err == nil {
			err = client.Ping(ctx, nil)
			if err == nil {
				cancel()
				break
			}
		}
		a.Log.Error().Err(err)
		cancel()
		time.Sleep(2 * time.Second)
		x++
	}

	if err != nil {
		a.Log.Fatal().Msgf("Failed to connect to MongoDB after %s seconds", timeout)
	}

	a.Mongo = client
	a.Log.Debug().Msg("Connected to MongoDB successfully ✓")
}

//-----------------------------------------------------------------------------
// InitialisePostgres
//-----------------------------------------------------------------------------

func (a *App) InitialisePostgres() {

	// due to postgres docker container not starting
	// up in time even with depends_on set we have to keep
	// trying to connect. if after 60 secs we still
	// haven't connected we log fatal and stop
	timeout := 60 * time.Second
	start := time.Now()
	var err error
	var gormDB *gorm.DB
	x := 1
	for time.Since(start) < timeout {
		a.Log.Debug().Msgf("Trying to connect to db...[%d]", x)
		gormDB, err = a.ConnectToPostgres()
		if err == nil {
			a.DB = &GormDB{db: gormDB}
			break
		}
		a.Log.Error().Err(err)
		time.Sleep(2 * time.Second)
		x++
	}

	if err != nil {
		a.Log.Fatal().Msgf("Failed to connect to the database after %s seconds", timeout)
	}

	a.Log.Debug().Msg("Connected to db successfully ✓")
	a.MigrateModels()
}

//-----------------------------------------------------------------------------
// connectToPostgres
//-----------------------------------------------------------------------------

func (a *App) ConnectToPostgres() (*gorm.DB, error) {

	dsn := fmt.Sprintf("user=%s password=%s dbname=%s host=%s port=%s sslmode=disable",
		os.Getenv("POSTGRES_USERNAME"),
		os.Getenv("POSTGRES_PASSWORD"),
		os.Getenv("POSTGRES_DBNAME"),
		os.Getenv("POSTGRES_HOST"),
		os.Getenv("POSTGRES_PORT"),
	)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, err
	}
	return db, nil
}

//-----------------------------------------------------------------------------
// MigrateModels
//-----------------------------------------------------------------------------

func (a *App) MigrateModels() {

	a.Log.Debug().Msg("Migrating models")

	err := a.DB.Migrator().AutoMigrate(&Role{}, &Cred{}, &Microservice{}, &SaveRecord{}, &RoleCredMS{}, &User{})
	if err != nil {
		a.Log.Fatal().Msg(err.Error())
	}
	// we have to migrate user separately due to dependencies on other models
	//err = a.DB.Migrator().AutoMigrate(&User{})
	//if err != nil {
	//	a.Log.Fatal().Msg(err.Error())
	//}
	a.Log.Debug().Msg("Models migrated successfully ✓")
}

//-----------------------------------------------------------------------------
// PopulatePostgresDB
//-----------------------------------------------------------------------------

func (a *App) PopulatePostgresDB() {

	var err error
	var aId *uuid.UUID

	if a.DB.Migrator().HasTable(&Role{}) {
		if err404 := a.DB.First(&Role{}).Error; errors.Is(err404, gorm.ErrRecordNotFound) {
			a.Log.Debug().Msg("No roles found. Creating roles")
			err = a.CreateRoles()
			if err != nil {
				a.Log.Error().Msgf("Unable to create roles [%s]", err.Error())
				a.Log.Fatal().Msg("Exiting...")
			}
		} else {
			a.Log.Debug().Msg("[Roles] table already populated ✓")
		}
	} else {
		a.Log.Fatal().Msg("[Roles] table not found")
	}

	var usr User
	if a.DB.Migrator().HasTable(&User{}) {
		if err404 := a.DB.First(&usr).Error; errors.Is(err404, gorm.ErrRecordNotFound) {
			a.Log.Debug().Msg("No users found. Creating user")
			aId, err = a.CreateSuperUser()
			if err != nil {
				a.Log.Error().Msg("Unable to create first user")
				a.Log.Fatal().Msg(err.Error())
			}
		} else {
			a.Log.Debug().Msg("[Users] table already populated ✓")
		}
	} else {
		a.Log.Fatal().Msg("[Users] table not found")
	}

	if aId == nil {
		aId = &usr.AdminId
	}

	// this step relies on superuser existing
	if a.DB.Migrator().HasTable(&Microservice{}) {
		if err404 := a.DB.First(&Microservice{}).Error; errors.Is(err404, gorm.ErrRecordNotFound) {
			a.Log.Debug().Msg("No microservices found. Creating microservices")
			err = a.CreateMicroservices(*aId)
			if err != nil {
				a.Log.Error().Msgf("Unable to create microservices [%s]", err.Error())
				a.Log.Fatal().Msg("Exiting...")
			}
		} else {
			a.Log.Debug().Msg("[Microservices] table already populated ✓")
		}
	} else {
		a.Log.Fatal().Msg("[Microservices] table not found")
	}

}

//-----------------------------------------------------------------------------
// CreateSuperUser
//-----------------------------------------------------------------------------

func (a *App) CreateSuperUser() (*uuid.UUID, error) {

	su, suExists := os.LookupEnv("SUPERUSER")
	pw, pwExists := os.LookupEnv("SUPERPASS")
	if !suExists || !pwExists {
		return nil, errors.New("superuser env vars not present in .env")
	}
	var pass []byte
	// password is base64 encoded
	pass, err := base64.StdEncoding.DecodeString(pw)
	if err != nil {
		a.Log.Info().Msgf("Base64 decoding failed [%s]", err.Error())
		return nil, err
	}
	var epw []byte
	epw, err = utils.GenerateHashPassword(pass)
	if err != nil {
		return nil, errors.New("unable to encrypt password")
	}

	r := Role{Name: "super"}
	res := a.DB.First(&r)
	if res.Error != nil {
		a.Log.Info().Msg("Unable to find 'super' role")
		return nil, res.Error
	}

	u := User{
		Username: su,
		Password: epw,
		Roles:    []Role{r},
	}

	res = a.DB.Create(&u)
	if res.Error != nil {
		return nil, res.Error
	}

	if os.Getenv("ENVIRONMENT") == "DEV" || os.Getenv("ENVIRONMENT") == "TEST" {

		if err = os.Setenv("CREATESUPER", "y"); err != nil {
			a.Log.Info().Msgf("Unable to set CREATESUPER env var [%s]", err.Error())
			return nil, err
		}
		u.Validated = true
		res = a.DB.Save(&u)
		if res.Error != nil {
			return nil, res.Error
		}
	}

	a.Log.Debug().Msgf("User created; AdminId is [%s] ✓", u.AdminId)

	return &u.AdminId, nil
}

//-----------------------------------------------------------------------------
// CreateRoles
//-----------------------------------------------------------------------------

func (a *App) CreateRoles() error {

	roles := []Role{
		{Name: "super"},
		{Name: "admin"},
		{Name: "aws"},
		{Name: "items"},
		{Name: "reviews"},
		{Name: "messages"},
		{Name: "auctionhouse"},
		{Name: "apiserver"},
		{Name: "categories"},
		{Name: "address"},
		{Name: "fotos"},
		{Name: "authy"},
		{Name: "list"},
	}
	res := a.DB.Create(&roles)
	if res.Error != nil {
		return res.Error
	}

	a.Log.Debug().Msg("Roles created ✓")
	return nil
}

//-----------------------------------------------------------------------------
// CreateMicroservices
//-----------------------------------------------------------------------------

func (a *App) CreateMicroservices(aId uuid.UUID) error {

	mss := []Microservice{
		{MSName: "aws", CreatedBy: aId},
		{MSName: "items", CreatedBy: aId},
		{MSName: "reviews", CreatedBy: aId},
		{MSName: "messages", CreatedBy: aId},
		{MSName: "auctionhouse", CreatedBy: aId},
		{MSName: "apiserver", CreatedBy: aId},
		{MSName: "categories", CreatedBy: aId},
		{MSName: "address", CreatedBy: aId},
		{MSName: "fotos", CreatedBy: aId},
		{MSName: "authy", CreatedBy: aId},
	}
	res := a.DB.Create(&mss)
	if res.Error != nil {
		return res.Error
	}

	a.Log.Debug().Msg("Microservices created ✓")
	return nil
}

//-----------------------------------------------------------------------------
// PrepSaveRestore
//-----------------------------------------------------------------------------

func (a *App) PrepSaveRestore(args *PrepSaveRestoreArgs) *PrepSaveRestoreResult {
	var creds Cred
	var user User
	var msID uuid.UUID

	// Use values from args struct
	dbName := args.DBName
	tabColl := args.TabColl
	mode := args.Mode
	c := args.Ctx

	// Validate mode
	validModes := []string{"schema", "all", "data"}
	if !slices.Contains(validModes, mode) {
		a.Log.Info().Msg("Invalid mode value")
		return &PrepSaveRestoreResult{
			StatusCode: http.StatusBadRequest,
			Error:      errors.New("Invalid mode value"),
			DBName:     dbName,
			TabColl:    tabColl,
			Mode:       mode,
		}
	}

	// Validate db and tab input
	if err := utils.ValidDataInput(dbName); err != nil {
		a.Log.Info().Msg("Invalid data input for db param")
		return &PrepSaveRestoreResult{
			StatusCode: http.StatusBadRequest,
			Error:      errors.New("Invalid data input for db param"),
			DBName:     dbName,
			TabColl:    tabColl,
			Mode:       mode,
		}
	}
	if err := utils.ValidDataInput(tabColl); err != nil {
		a.Log.Info().Msg("Invalid data input for table/collection param")
		return &PrepSaveRestoreResult{
			StatusCode: http.StatusBadRequest,
			Error:      errors.New("Invalid data input for table/collection param"),
			DBName:     dbName,
			TabColl:    tabColl,
			Mode:       mode,
		}
	}

	// Get cred_id and ms_id from gin context params
	var credId uuid.UUID
	if err := a.GetUUIDFromParams(c, &credId, "cred_id"); err != nil {
		a.Log.Info().Msgf("Error getting uuid from params [%s]", err.Error())
		return &PrepSaveRestoreResult{
			StatusCode: http.StatusBadRequest,
			Error:      errors.New("Error getting uuid from cred param"),
			DBName:     dbName,
			TabColl:    tabColl,
			Mode:       mode,
		}
	}
	if err := a.GetUUIDFromParams(c, &msID, "ms_id"); err != nil {
		a.Log.Info().Msgf("Error getting uuid from params [%s]", err.Error())
		return &PrepSaveRestoreResult{
			StatusCode: http.StatusBadRequest,
			Error:      errors.New("Error getting uuid from ms param"),
			DBName:     dbName,
			TabColl:    tabColl,
			Mode:       mode,
		}
	}

	a.Log.Debug().Msgf("Input vars are: credId [%s], db [%s], tabColl [%s], mode [%s]", credId.String(), dbName, tabColl, mode)

	// Fetch creds record
	creds.CredId = credId
	res := a.DB.First(&creds, credId)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			a.Log.Info().Msgf("Creds [%s] not found", credId.String())
			return &PrepSaveRestoreResult{
				StatusCode: http.StatusNotFound,
				Error:      errors.New("Creds not found"),
				DBName:     dbName,
				TabColl:    tabColl,
				Mode:       mode,
			}
		}
		a.Log.Info().Msgf("Error finding creds [%s]", res.Error.Error())
		return &PrepSaveRestoreResult{
			StatusCode: http.StatusInternalServerError,
			Error:      errors.New("Something went pop"),
			DBName:     dbName,
			TabColl:    tabColl,
			Mode:       mode,
		}
	}

	if dbName != creds.DBName {
		a.Log.Info().Msgf("DB name [%v] is incorrect", dbName)
		return &PrepSaveRestoreResult{
			StatusCode: http.StatusNotFound,
			Error:      errors.New("DB name is invalid"),
			DBName:     dbName,
			TabColl:    tabColl,
			Mode:       mode,
		}
	}

	// Get user from gin context
	var i interface{}
	i, _ = c.Get("user")
	user = i.(User)
	// as getting consumes the resource we have to reset it
	c.Set("user", user)

	return &PrepSaveRestoreResult{
		StatusCode: http.StatusOK,
		Error:      nil,
		Creds:      creds,
		User:       user,
		MSId:       msID,
		DBName:     dbName,
		TabColl:    tabColl,
		Mode:       mode,
	}
}

//-----------------------------------------------------------------------------
// BackupPostgres
//-----------------------------------------------------------------------------

func (a *App) BackupPostgres(args *BackupDBArgs) error {
	pw, err := a.decryptPassword(args.Creds.DBPassword)
	if err != nil {
		return err
	}

	dso := ""
	if args.Mode == "schema" {
		dso = "--schema-only"
	} else if args.Mode == "data" {
		dso = "--data-only"
	}

	cmdArgs := []string{
		"-h", args.Creds.Host,
		"-U", args.Creds.DBUsername,
		"-p", args.Creds.DBPort,
	}
	if args.Table != "" {
		cmdArgs = append(cmdArgs, "-t", args.Table)
	}
	if dso != "" {
		cmdArgs = append(cmdArgs, dso)
	}
	cmdArgs = append(cmdArgs, args.Creds.DBName)
	a.Log.Debug().Msgf("pg_dump args is <<%s>>", cmdArgs)

	env := []string{"PGPASSWORD=" + string(pw)}
	var cmd Cmd
	var stdout io.ReadCloser
	cmd, stdout, err = a.setupAndStartCmd("pg_dump", cmdArgs, env, "pg_dump")
	if err != nil {
		return err
	}

	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("%s_%s.sql", args.MsId.String(), timestamp)

	metadata := map[string]interface{}{
		"created_at": time.Now(),
		"created_by": args.User.AdminId.String(),
		"save_id":    args.SaveId.String(),
		"ms_id":      args.MsId.String(),
		"mode":       args.Mode,
		"db":         args.Creds.DBName,
		"table":      args.Table,
	}

	uploadStream, err := a.createGridFSUploadStream(args.DB, filename, metadata)
	if err != nil {
		return err
	}
	defer uploadStream.Close()

	*args.BytesWritten, err = a.copyToGridFS(uploadStream, stdout, "pg_dump")
	if err != nil {
		return err
	}

	if err = cmd.Wait(); err != nil {
		a.Log.Info().Msgf("pg_dump cmd.Wait error [%s]", err.Error())
		return err
	}
	a.Log.Debug().Msg("Successfully streamed Postgres dump to GridFS ✓")

	sr := SaveRecord{
		SaveId:         *args.SaveId,
		MicroserviceId: *args.MsId,
		CredId:         args.Creds.CredId,
		DBName:         args.Creds.DBName,
		Table:          args.Table,
		SavedBy:        args.User.Username,
		Version:        0,
		Dataset:        0,
		Mode:           args.Mode,
		Valid:          true,
		Type:           args.Creds.Type,
		Size:           *args.BytesWritten,
	}
	if err = a.SaveWithAutoVersion(&sr); err != nil {
		a.Log.Info().Msgf("Unable to insert save record [%s]", err.Error())
		return err
	}
	a.Log.Debug().Msg("Successfully inserted SaveRecord ✓")
	return nil
}

//-----------------------------------------------------------------------------
// backupMongo
//-----------------------------------------------------------------------------

func (a *App) BackupMongo(args *BackupDBArgs) error {
	pw, err := a.decryptPassword(args.Creds.DBPassword)
	if err != nil {
		return err
	}

	cmdArgs := []string{"--archive"}
	db := args.Creds.DBName // ensure DB name is from creds

	if args.Table != "" {
		cmdArgs = append(cmdArgs, "--collection", args.Table)
	}

	mus := fmt.Sprintf("--uri=\"mongodb://%s:%s@%s:%s/%s?authSource=%s\"",
		args.Creds.DBUsername, string(pw), args.Creds.Host, args.Creds.DBPort, args.Creds.DBName, args.Creds.DBName)
	cmdArgs = append(cmdArgs, mus)
	a.Log.Debug().Msgf("mongodump args is <<%s>>", cmdArgs)

	var cmd Cmd
	var stdout io.ReadCloser
	cmd, stdout, err = a.setupAndStartCmd("mongodump", cmdArgs, nil, "mongodump")
	if err != nil {
		return err
	}

	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("%s_%s.archive", args.MsId.String(), timestamp)

	metadata := map[string]interface{}{
		"created_at": time.Now(),
		"created_by": args.User.AdminId.String(),
		"save_id":    args.SaveId.String(),
		"ms_id":      args.MsId.String(),
		"mode":       args.Mode,
		"db":         args.Creds.DBName,
		"collection": args.Table,
	}

	uploadStream, err := a.createGridFSUploadStream(db, filename, metadata)
	if err != nil {
		return err
	}
	defer uploadStream.Close()

	*args.BytesWritten, err = a.copyToGridFS(uploadStream, stdout, "mongodump")
	if err != nil {
		return err
	}

	if err = cmd.Wait(); err != nil {
		a.Log.Info().Msgf("mongodump cmd.Wait error [%s]", err.Error())
		return err
	}
	a.Log.Debug().Msg("Successfully streamed MongoDB dump to GridFS ✓")

	// Create SaveRecord!
	sr := SaveRecord{
		SaveId:         *args.SaveId,
		MicroserviceId: *args.MsId,
		CredId:         args.Creds.CredId,
		DBName:         args.Creds.DBName,
		Table:          args.Table, // Table = collection for mongo
		SavedBy:        args.User.Username,
		Version:        0,
		Dataset:        0,
		Mode:           args.Mode,
		Valid:          true,
		Type:           args.Creds.Type,
		Size:           *args.BytesWritten,
	}
	if err = a.SaveWithAutoVersion(&sr); err != nil {
		a.Log.Info().Msgf("Unable to insert save record [%s]", err.Error())
		return err
	}
	a.Log.Debug().Msg("Successfully inserted SaveRecord ✓")

	return nil
}

//-----------------------------------------------------------------------------
// RestoreMongo
//-----------------------------------------------------------------------------

func (a *App) RestoreMongo(dba RestoreDBArgs) (int, string, error) {
	//	c *gin.Context,
	//	svRec *SaveRecord,
	//	crdRec *Cred,
	//	pw *[]byte,
	//	downloadStream *gridfs.DownloadStream,
	//) {
	var err error
	var stdoutBuf, stderrBuf bytes.Buffer

	// Drop logic using WriteMongoOut, like WriteSQLOut for Postgres
	if dba.Save.Mode == "schema" || dba.Save.Mode == "all" {
		if dba.Save.Table != "" {
			dropCmd := fmt.Sprintf("db.%s.drop()", dba.Save.Table)
			_, err = a.WriteMongoOut(*dba.MongoContext, dropCmd, dba.Creds, dba.Password)
			if err != nil {
				return http.StatusInternalServerError, "Failed to drop collection before restore", err

			}
			a.Log.Debug().Msgf("Dropped collection [%s]", dba.Save.Table)
		} else {
			dropCmd := `db.getCollectionNames().forEach(function(Con){db[Con].drop();})`
			_, err = a.WriteMongoOut(*dba.MongoContext, dropCmd, dba.Creds, dba.Password)
			if err != nil {
				return http.StatusInternalServerError, "Failed to drop all collections before restore", err
			}
			a.Log.Debug().Msg("Dropped all collections")
		}
	}

	// Prepare mongorestore as before
	uri := fmt.Sprintf(
		"mongodb://%s:%s@%s:%s/%s?authSource=%s",
		dba.Creds.DBUsername,
		string(*dba.Password),
		dba.Creds.Host,
		dba.Creds.DBPort,
		dba.Creds.DBName,
		dba.Creds.DBName,
	)

	args := []string{"--uri=" + uri, "--archive"}
	if dba.Save.Table != "" {
		//	args = append(args, "--nsInclude", fmt.Sprintf("%s.%s", crdRec.DBName, svRec.Table))
		args = append(args, "--nsInclude="+fmt.Sprintf("%s.%s", dba.Creds.DBName, dba.Save.Table))
	}
	a.Log.Debug().Msgf("mongorestore args: %v", args)

	cmd := a.CommandRunner.Command("mongorestore", args...)
	cmd.SetStdout(&stdoutBuf)
	cmd.SetStderr(&stderrBuf)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		a.Log.Info().Msgf("Error getting StdinPipe for mongorestore: %s", err.Error())
		return http.StatusInternalServerError, "Error preparing mongorestore", err
	}
	defer stdin.Close()

	if err = cmd.Start(); err != nil {
		a.Log.Info().Msgf("Error starting mongorestore: %s", err.Error())
		return http.StatusInternalServerError, "Error starting mongorestore", err
	}
	a.Log.Debug().Msg("Started mongorestore ✓")

	n, err := io.Copy(stdin, dba.DownloadStream)
	stdin.Close()
	a.Log.Debug().Msgf("Copied %d bytes from GridFS to mongorestore stdin", n)
	if err != nil {
		a.Log.Info().Msgf("Error streaming to mongorestore: %s", err.Error())
		return http.StatusInternalServerError, "Error streaming to mongorestore", err
	}
	a.Log.Debug().Msg("Closed stdin ✓")

	if err = cmd.Wait(); err != nil {
		a.Log.Info().Msgf("mongorestore failed: %s", err.Error())
		a.Log.Info().Msgf("stdout: %s", stdoutBuf.String())
		a.Log.Info().Msgf("stderr: %s", stderrBuf.String())
		return http.StatusInternalServerError, "mongorestore failed", err

	}
	a.Log.Debug().Msg("mongorestore completed successfully ✓")

	return http.StatusOK, "Mongo restore succeeded!", nil
}

//-----------------------------------------------------------------------------
// RestorePostgres
//-----------------------------------------------------------------------------

func (a *App) RestorePostgres(DbArgs *RestoreDBArgs) (int, string) {

	var err error
	var stdoutBuf, stderrBuf bytes.Buffer

	wso := WriteSQLArgs{
		SQLStatement: "",
		Creds:        DbArgs.Creds,
		Password:     DbArgs.Password,
		ReturnTables: false,
	}

	// Drop/delete logic based on svRec.Mode
	if DbArgs.Save.Mode == "schema" || DbArgs.Save.Mode == "all" {
		if DbArgs.Save.Table != "" {
			wso.SQLStatement = fmt.Sprintf("DROP TABLE %s", DbArgs.Save.Table)
			_, err = a.Hooks.WriteSQLOut(&wso)
			if err != nil {
				return http.StatusInternalServerError, "Something went plink"
			} else {
				a.Log.Debug().Msgf("Successfully dropped table [%s] ✓", DbArgs.Save.Table)
			}
		} else {
			// TODO: Refactor this
			var tabs []string
			tabs, err = a.ListTables(DbArgs.Creds, DbArgs.Password)
			if err != nil {
				a.Log.Info().Msgf("Error listing tables [%s]", err.Error())
				return http.StatusInternalServerError, "Something went scree"
			}
			for _, table := range tabs {
				a.Log.Debug().Msgf("Table is [%s]", table)
				wso.SQLStatement = fmt.Sprintf("DROP TABLE %s CASCADE", table)
				_, err = a.Hooks.WriteSQLOut(&wso)
				if err != nil {
					a.Log.Info().Msgf("Error: [%s]", err.Error())
					return http.StatusInternalServerError, "Something went twang"
				} else {
					a.Log.Debug().Msgf("Successfully dropped table [%s] ✓", table)
				}
			}
		}
	} else if DbArgs.Save.Mode == "data" {
		if DbArgs.Save.Table != "" {
			wso.SQLStatement = fmt.Sprintf("DELETE FROM %s;", DbArgs.Save.Table)
			_, err = a.Hooks.WriteSQLOut(&wso)
			if err != nil {
				a.Log.Info().Msgf("Error: [%s]", err.Error())
				return http.StatusInternalServerError, "Something went kerplunk"
			} else {
				a.Log.Debug().Msgf("Successfully deleted data from table [%s] ✓", DbArgs.Save.Table)
			}
		} else {
			var sc int
			sc, err = a.PostgresDeleteAllRecs(DbArgs.Creds, DbArgs.Password)
			if err != nil {
				a.Log.Info().Msgf("Error: [%s]", err.Error())
				return sc, "Something went splat"
			}
		}
	}

	// build psql arguments
	args := []string{
		"-h", DbArgs.Creds.Host,
		"-U", DbArgs.Creds.DBUsername,
		"-p", DbArgs.Creds.DBPort,
		"-d", DbArgs.Creds.DBName,
		"-f", "-",
		"-v", "ON_ERROR_STOP=1",
	}
	a.Log.Debug().Msgf("args is <<%s>>", args)
	cmd := a.CommandRunner.Command("psql", args...)
	cmd.SetEnv(append(os.Environ(), "PGPASSWORD="+string(*DbArgs.Password)))
	a.Log.Debug().Msg("After CommandRunner.Command ✓")

	cmd.SetStdout(&stdoutBuf)
	cmd.SetStderr(&stderrBuf)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		a.Log.Info().Msgf("WriteCloser error [%s]", err.Error())
		return http.StatusInternalServerError, "Something went donk"
	}
	defer stdin.Close()
	a.Log.Debug().Msg("After defer stdin.Close ✓")

	if err = cmd.Start(); err != nil {
		a.Log.Info().Msgf("cmd.Start error [%s]", err.Error())
		return http.StatusInternalServerError, "Something went twong"
	}
	a.Log.Debug().Msg("After cmd.Start ✓")

	_, err = io.Copy(stdin, DbArgs.DownloadStream)
	if err != nil {
		a.Log.Info().Msgf("io.Copy error [%s]", err.Error())
		return http.StatusInternalServerError, "Something went splash"
	}
	stdin.Close()
	a.Log.Debug().Msg("After stdin.Close ✓")

	if err = cmd.Wait(); err != nil {
		a.Log.Info().Msgf("psql failed: %s\nstderr: %s\nstdout: %s", err.Error(), stderrBuf.String(), stdoutBuf.String())
		return http.StatusInternalServerError, "psql failed"
	}
	a.Log.Debug().Msgf("stderr: [%s]", stderrBuf.String())
	a.Log.Debug().Msgf("stdout: [%s]", stdoutBuf.String())
	return http.StatusOK, "Postgres restore succeeded!"
}

//-----------------------------------------------------------------------------
// PostgresDeleteAllRecs
//-----------------------------------------------------------------------------

func (a *App) PostgresDeleteAllRecs(crd *Cred, pw *[]byte) (int, error) {

	//var tabs []string
	tabs, err := a.ListTables(crd, pw)
	if err != nil {
		a.Log.Info().Msgf("Error listing tables [%s]", err.Error())
		return http.StatusInternalServerError, errors.New("error listing tables")
	}
	for _, table := range tabs {
		a.Log.Debug().Msgf("Table is [%s]", table)
		wso := WriteSQLArgs{
			SQLStatement: fmt.Sprintf("DELETE FROM %s;", table),
			Creds:        crd,
			Password:     pw,
			ReturnTables: false,
		}
		_, err = a.Hooks.WriteSQLOut(&wso)
		if err != nil {
			return http.StatusInternalServerError, err
		} else {
			a.Log.Debug().Msgf("Data successfully deleted from table [%s] ✓", table)
		}
	}
	return http.StatusOK, nil
}

//-----------------------------------------------------------------------------
// DeleteGridFSBySaveID
//-----------------------------------------------------------------------------

func (a *App) DeleteGridFSBySaveID(c *gin.Context, saveID string, dbName string) error {

	filesColl := a.Mongo.Database(dbName).Collection("fs.files")
	chunksColl := a.Mongo.Database(dbName).Collection("fs.chunks")
	ctx := c.Request.Context()

	// Find all files with the given save_id
	cursor, err := filesColl.Find(ctx, bson.M{"metadata.save_id": saveID})
	if err != nil {
		return err
	}
	defer cursor.Close(ctx)

	var fileIDs []interface{}
	for cursor.Next(ctx) {
		var fileDoc struct {
			ID interface{} `bson:"_id"`
		}
		if err = cursor.Decode(&fileDoc); err != nil {
			return err
		}
		fileIDs = append(fileIDs, fileDoc.ID)
	}
	if err = cursor.Err(); err != nil {
		return err
	}
	if len(fileIDs) == 0 {
		return errors.New("no files found with given save_id")
	}

	// Delete files from fs.files
	_, err = filesColl.DeleteMany(ctx, bson.M{"_id": bson.M{"$in": fileIDs}})
	if err != nil {
		return err
	}

	// Delete corresponding chunks from fs.chunks
	_, err = chunksColl.DeleteMany(ctx, bson.M{"files_id": bson.M{"$in": fileIDs}})
	return err
}
