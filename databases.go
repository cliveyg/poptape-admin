package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/cliveyg/poptape-admin/utils"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/gridfs"
	"go.mongodb.org/mongo-driver/mongo/options"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"io"
	"net/http"
	"os"
	"os/exec"
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
		a.Log.Info().Msgf("Trying to connect to MongoDB...[%d]", x)
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
	a.Log.Info().Msg("Connected to MongoDB successfully ✓")
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
	x := 1
	for time.Since(start) < timeout {
		a.Log.Info().Msgf("Trying to connect to db...[%d]", x)
		a.DB, err = connectToPostgres()
		if err == nil {
			break
		}
		a.Log.Error().Err(err)
		time.Sleep(2 * time.Second)
		x++
	}

	if err != nil {
		a.Log.Fatal().Msgf("Failed to connect to the database after %s seconds", timeout)
	}

	a.Log.Info().Msg("Connected to db successfully ✓")
	a.MigrateModels()
}

//-----------------------------------------------------------------------------
// connectToPostgres
//-----------------------------------------------------------------------------

func connectToPostgres() (*gorm.DB, error) {

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

	a.Log.Info().Msg("Migrating models")
	err := a.DB.AutoMigrate(&Role{}, &Cred{}, &Microservice{}, &SaveRecord{}, &RoleCredMS{})
	if err != nil {
		a.Log.Fatal().Msg(err.Error())
	}
	// we have to migrate user separately due to dependencies on other models
	err = a.DB.AutoMigrate(&User{})
	if err != nil {
		a.Log.Fatal().Msg(err.Error())
	}
	a.Log.Info().Msg("Models migrated successfully ✓")
}

//-----------------------------------------------------------------------------
// PopulatePostgresDB
//-----------------------------------------------------------------------------

func (a *App) PopulatePostgresDB() {

	var err error
	var aId *uuid.UUID

	if a.DB.Migrator().HasTable(&Role{}) {
		if err404 := a.DB.First(&Role{}).Error; errors.Is(err404, gorm.ErrRecordNotFound) {
			a.Log.Info().Msg("No roles found. Creating roles")
			err = a.CreateRoles()
			if err != nil {
				a.Log.Error().Msgf("Unable to create roles [%s]", err.Error())
				a.Log.Fatal().Msg("Exiting...")
			}
		} else {
			a.Log.Info().Msg("[Roles] table already populated ✓")
		}
	} else {
		a.Log.Fatal().Msg("[Roles] table not found")
	}

	var usr User
	if a.DB.Migrator().HasTable(&User{}) {
		if err404 := a.DB.First(&usr).Error; errors.Is(err404, gorm.ErrRecordNotFound) {
			a.Log.Info().Msg("No users found. Creating user")
			aId, err = a.CreateSuperUser()
			if err != nil {
				a.Log.Error().Msg("Unable to create first user")
				a.Log.Fatal().Msg(err.Error())
			}
		} else {
			a.Log.Info().Msg("[Users] table already populated ✓")
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
			a.Log.Info().Msg("No microservices found. Creating microservices")
			err = a.CreateMicroservices(*aId)
			if err != nil {
				a.Log.Error().Msgf("Unable to create microservices [%s]", err.Error())
				a.Log.Fatal().Msg("Exiting...")
			}
		} else {
			a.Log.Info().Msg("[Microservices] table already populated ✓")
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

	if os.Getenv("ENVIRONMENT") == "DEV" {

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
	}
	res := a.DB.Create(&roles)
	if res.Error != nil {
		return res.Error
	}

	a.Log.Info().Msg("Roles created ✓")
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

	a.Log.Info().Msg("Microservices created ✓")
	return nil
}

//-----------------------------------------------------------------------------
// backupPostgres
//-----------------------------------------------------------------------------

func (a *App) backupPostgres(creds *Cred, msId *uuid.UUID, u *User, db, table, mode string, saveId *uuid.UUID) error {

	key := []byte(os.Getenv("SUPERSECRETKEY"))
	nonce := []byte(os.Getenv("SUPERSECRETNONCE"))
	pw, err := utils.Decrypt(creds.DBPassword, key, nonce)
	if err != nil {
		a.Log.Info().Msgf("Error decrypting password from creds [%s]", err.Error())
		return err
	}
	a.Log.Debug().Msg("Successfully decrypted password ✓")

	mdb := a.Mongo.Database(db)
	bucket, err := gridfs.NewBucket(mdb)
	if err != nil {
		return err
	}
	a.Log.Debug().Msg("Successfully created bucket ✓")

	dso := ""
	if mode == "schema" {
		dso = "--schema-only"
	} else if mode == "data" {
		dso = "--data-only"
	}

	// build pg_dump arguments
	args := []string{
		"-h", creds.Host,
		"-U", creds.DBUsername,
		"-p", creds.DBPort,
	}
	if table != "" {
		args = append(args, "-t")
		args = append(args, table)
	}
	if dso != "" {
		args = append(args, dso)
	}
	args = append(args, creds.DBName)

	a.Log.Debug().Msgf("args is <<%s>>", args)

	cmd := exec.Command("pg_dump", args...)
	cmd.Env = append(os.Environ(), "PGPASSWORD="+string(pw))

	var stdout, stderr io.ReadCloser
	stdout, err = cmd.StdoutPipe()
	if err != nil {
		a.Log.Info().Msgf("Error from StdoutPipe [%s]", err.Error())
		return err
	}

	stderr, err = cmd.StderrPipe()
	if err != nil {
		a.Log.Info().Msgf("Error from StderrPipe [%s]", err.Error())
		return err
	}
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			a.Log.Info().Msgf("[pg_dump stderr] %s", scanner.Text())
		}
	}()

	if err = cmd.Start(); err != nil {
		a.Log.Info().Msgf("Error starting cmd [%s]", err.Error())
		return err
	}
	a.Log.Debug().Msg("Successfully started cmd ✓")

	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("%s_%s.sql", msId.String(), timestamp)
	var uploadStream *gridfs.UploadStream
	uploadStream, err = bucket.OpenUploadStream(
		filename,
		options.GridFSUpload().SetMetadata(map[string]interface{}{
			"created_at": time.Now(),
			"created_by": u.AdminId.String(),
			"save_id":    saveId.String(),
			"ms_id":      msId.String(),
			"mode":       mode,
		}),
	)
	if err != nil {
		a.Log.Info().Msgf("Error opening upload stream [%s]", err.Error())
		return err
	}
	defer uploadStream.Close()
	a.Log.Debug().Msg("Successfully opened upload stream ✓")

	if _, err = io.Copy(uploadStream, stdout); err != nil {
		a.Log.Info().Msgf("Error copying data to uploadStream [%s]", err.Error())
		return err
	}
	if err = cmd.Wait(); err != nil {
		a.Log.Info().Msgf("cmd.Wait error [%s]", err.Error())
		return err
	}
	a.Log.Debug().Msg("Successfully streamed data to mongo ✓")

	sr := SaveRecord{
		SaveId:         *saveId,
		MicroserviceId: *msId,
		CredId:         creds.CredId,
		SavedBy:        u.Username,
		Dataset:        0,
		Mode:           mode,
		Type:           creds.Type,
		DBName:         creds.DBUsername,
		Table:          table,
		Valid:          true,
	}

	if err = a.SaveWithAutoVersion(&sr); err != nil {
		a.Log.Info().Msgf("Unable to insert save record [%s]", err.Error())
		return err
	}
	a.Log.Debug().Msg("Successfully inserted SaveRecord ✓")

	// TODO: update creds with last used deets

	return nil
}

//-----------------------------------------------------------------------------
// backupMongo
//-----------------------------------------------------------------------------

func (a *App) backupMongo(creds *Cred, msId *uuid.UUID, u *User, db, collection, mode string, saveId *uuid.UUID) error {
	// build mongodump args
	args := []string{
		"--archive",
	}
	// TODO: fix this properly
	db = creds.DBName

	if collection != "" {
		args = append(args, "--collection", collection)
	}

	key := []byte(os.Getenv("SUPERSECRETKEY"))
	nonce := []byte(os.Getenv("SUPERSECRETNONCE"))
	pw, err := utils.Decrypt(creds.DBPassword, key, nonce)
	mus := fmt.Sprintf("--uri=\"mongodb://%s:%s@%s:%s/%s?authSource=%s\"", creds.DBUsername,
		pw,
		creds.Host,
		creds.DBPort,
		creds.DBName,
		creds.DBName)
	args = append(args, mus)
	a.Log.Debug().Msgf("mongodump args is <<%s>>", args)

	cmd := exec.Command("mongodump", args...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		a.Log.Info().Msgf("Error from StdoutPipe [%s]", err.Error())
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		a.Log.Info().Msgf("Error from StderrPipe [%s]", err.Error())
		return err
	}

	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			a.Log.Info().Msgf("[mongodump stderr] %s", scanner.Text())
		}
	}()

	if err = cmd.Start(); err != nil {
		a.Log.Info().Msgf("Error starting mongodump [%s]", err.Error())
		return err
	}
	a.Log.Debug().Msg("Successfully started mongodump ✓")

	// Use the same Mongo bucket as for Postgres backups
	mdb := a.Mongo.Database(db)
	bucket, err := gridfs.NewBucket(mdb)
	if err != nil {
		return err
	}
	a.Log.Debug().Msg("Successfully created bucket ✓")

	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("%s_%s.archive", msId.String(), timestamp)

	uploadStream, err := bucket.OpenUploadStream(
		filename,
		options.GridFSUpload().SetMetadata(map[string]interface{}{
			"created_at": time.Now(),
			"created_by": u.AdminId.String(),
			"save_id":    saveId.String(),
			"ms_id":      msId.String(),
			"mode":       mode,
			"db":         db,
			"collection": collection,
		}),
	)
	if err != nil {
		a.Log.Info().Msgf("Error opening upload stream [%s]", err.Error())
		return err
	}
	defer uploadStream.Close()
	a.Log.Debug().Msg("Successfully opened upload stream ✓")

	var n int64
	if n, err = io.Copy(uploadStream, stdout); err != nil {
		a.Log.Info().Msgf("Error copying data to uploadStream [%s]", err.Error())
		return err
	}
	a.Log.Debug().Msgf("Copied %d bytes from GridFS to stdin", n)
	if err = cmd.Wait(); err != nil {
		a.Log.Info().Msgf("cmd.Wait error [%s]", err.Error())
		return err
	}
	a.Log.Debug().Msg("Successfully streamed MongoDB dump to GridFS ✓")

	sr := SaveRecord{
		SaveId:         *saveId,
		MicroserviceId: *msId,
		CredId:         creds.CredId,
		SavedBy:        u.Username,
		Dataset:        0,
		Mode:           mode,
		Type:           creds.Type,
		DBName:         creds.DBUsername,
		Table:          collection,
		Valid:          true,
	}

	if err = a.SaveWithAutoVersion(&sr); err != nil {
		a.Log.Info().Msgf("Unable to insert save record [%s]", err.Error())
		return err
	}
	a.Log.Debug().Msg("Successfully inserted SaveRecord ✓")

	// TODO: update creds with last used deets

	return nil
}

//-----------------------------------------------------------------------------
// RestoreMongo
//-----------------------------------------------------------------------------

func (a *App) RestoreMongo(
	c *gin.Context,
	svRec *SaveRecord,
	crdRec *Cred,
	pw *[]byte,
	downloadStream *gridfs.DownloadStream,
) {
	var err error
	var stdoutBuf, stderrBuf bytes.Buffer

	// Drop logic using writeMongoOut, like writeSQLOut for Postgres
	if svRec.Mode == "schema" || svRec.Mode == "all" {
		if svRec.Table != "" {
			dropCmd := fmt.Sprintf("db.%s.drop()", svRec.Table)
			_, err = a.writeMongoOut(c, dropCmd, crdRec, pw)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to drop collection before restore"})
				return
			}
			a.Log.Debug().Msgf("Dropped collection [%s]", svRec.Table)
		} else {
			dropCmd := `db.getCollectionNames().forEach(function(c){db[c].drop();})`
			_, err = a.writeMongoOut(c, dropCmd, crdRec, pw)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to drop all collections before restore"})
				return
			}
			a.Log.Debug().Msg("Dropped all collections")
		}
	}

	// Prepare mongorestore as before
	uri := fmt.Sprintf(
		"mongodb://%s:%s@%s:%s/%s?authSource=%s",
		crdRec.DBUsername,
		string(*pw),
		crdRec.Host,
		crdRec.DBPort,
		crdRec.DBName,
		crdRec.DBName,
	)

	args := []string{"--uri=" + uri, "--archive"}
	if svRec.Table != "" {
		//	args = append(args, "--nsInclude", fmt.Sprintf("%s.%s", crdRec.DBName, svRec.Table))
		args = append(args, "--nsInclude="+fmt.Sprintf("%s.%s", crdRec.DBName, svRec.Table))
	}
	a.Log.Debug().Msgf("mongorestore args: %v", args)

	cmd := exec.Command("mongorestore", args...)
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	stdin, err := cmd.StdinPipe()
	if err != nil {
		a.Log.Info().Msgf("Error getting StdinPipe for mongorestore: %s", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Error preparing mongorestore"})
		return
	}
	defer stdin.Close()

	if err = cmd.Start(); err != nil {
		a.Log.Info().Msgf("Error starting mongorestore: %s", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Error starting mongorestore"})
		return
	}
	a.Log.Debug().Msg("Started mongorestore ✓")

	n, err := io.Copy(stdin, downloadStream)
	stdin.Close()
	a.Log.Debug().Msgf("Copied %d bytes from GridFS to mongorestore stdin", n)
	if err != nil {
		a.Log.Info().Msgf("Error streaming to mongorestore: %s", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Error streaming to mongorestore"})
		return
	}
	a.Log.Debug().Msg("Closed stdin ✓")

	if err = cmd.Wait(); err != nil {
		a.Log.Info().Msgf("mongorestore failed: %s", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "mongorestore failed",
			"stderr":  stderrBuf.String(),
			"stdout":  stdoutBuf.String(),
		})
		return
	}
	a.Log.Debug().Msg("mongorestore completed successfully ✓")
	c.JSON(http.StatusOK, gin.H{
		"message":  "Mongo restore succeeded!",
		"stderr":   stderrBuf.String(),
		"stdout":   stdoutBuf.String(),
		"save_rec": svRec,
	})
}

//-----------------------------------------------------------------------------
// RestorePostgres
//-----------------------------------------------------------------------------

func (a *App) RestorePostgres(
	c *gin.Context,
	svRec *SaveRecord,
	crdRec *Cred,
	pw *[]byte,
	downloadStream *gridfs.DownloadStream, // (can be *gridfs.DownloadStream, but io.Reader is general)
) {
	var err error
	var stdoutBuf, stderrBuf bytes.Buffer

	// Drop/delete logic based on svRec.Mode
	if svRec.Mode == "schema" || svRec.Mode == "all" {
		if svRec.Table != "" {
			dc := fmt.Sprintf("DROP TABLE %s", svRec.Table)
			_, err = a.writeSQLOut(dc, crdRec, pw, false)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went plink"})
				return
			} else {
				a.Log.Debug().Msgf("Successfully dropped table [%s] ✓", svRec.Table)
			}
		} else {
			var tabs []string
			tabs, err = a.listTables(crdRec, pw)
			if err != nil {
				a.Log.Info().Msgf("Error listing tables [%s]", err.Error())
				c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went scree"})
				return
			}
			for _, table := range tabs {
				a.Log.Debug().Msgf("Table is [%s]", table)
				dc := fmt.Sprintf("DROP TABLE %s", table)
				_, err = a.writeSQLOut(dc, crdRec, pw, false)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went plink"})
					return
				} else {
					a.Log.Debug().Msgf("Successfully dropped table [%s] ✓", table)
				}
			}
		}
	} else if svRec.Mode == "data" {
		if svRec.Table != "" {
			dc := fmt.Sprintf("DELETE FROM %s;", svRec.Table)
			_, err = a.writeSQLOut(dc, crdRec, pw, false)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went plink"})
				return
			} else {
				a.Log.Debug().Msgf("Successfully deleted data from table [%s] ✓", svRec.Table)
			}
		} else {
			var tabs []string
			tabs, err = a.listTables(crdRec, pw)
			if err != nil {
				a.Log.Info().Msgf("Error listing tables [%s]", err.Error())
				c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went scree"})
				return
			}
			for _, table := range tabs {
				a.Log.Debug().Msgf("Table is [%s]", table)
				dc := fmt.Sprintf("DELETE FROM %s;", table)
				_, err = a.writeSQLOut(dc, crdRec, pw, false)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went plink"})
					return
				} else {
					a.Log.Debug().Msgf("Successfully deleted from table [%s] ✓", table)
				}
			}
		}
	}

	// build psql arguments
	args := []string{
		"-h", crdRec.Host,
		"-U", crdRec.DBUsername,
		"-p", crdRec.DBPort,
		"-d", crdRec.DBName,
		"-f", "-",
		"-v", "ON_ERROR_STOP=1",
	}
	a.Log.Debug().Msgf("args is <<%s>>", args)
	cmd := exec.Command("psql", args...)
	cmd.Env = append(os.Environ(), "PGPASSWORD="+string(*pw))
	a.Log.Debug().Msg("After exec.Command ✓")

	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	stdin, err := cmd.StdinPipe()
	if err != nil {
		a.Log.Info().Msgf("WriteCloser error [%s]", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went ping"})
		return
	}
	defer stdin.Close()
	a.Log.Debug().Msg("After defer stdin.Close ✓")

	if err = cmd.Start(); err != nil {
		a.Log.Info().Msgf("cmd.Start error [%s]", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went twang"})
		return
	}
	a.Log.Debug().Msg("After cmd.Start ✓")

	_, err = io.Copy(stdin, downloadStream)
	if err != nil {
		a.Log.Info().Msgf("io.Copy error [%s]", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went splash"})
		return
	}
	stdin.Close()
	a.Log.Debug().Msg("After stdin.Close ✓")

	if err = cmd.Wait(); err != nil {
		a.Log.Debug().Msgf("psql failed: %s\nstderr: %s\nstdout: %s", err.Error(), stderrBuf.String(), stdoutBuf.String())
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "psql failed",
			"stderr":  stderrBuf.String(),
			"stdout":  stdoutBuf.String(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message":  "Postgres restore succeeded!",
		"stderr":   stderrBuf.String(),
		"stdout":   stdoutBuf.String(),
		"save_rec": svRec,
	})
}
