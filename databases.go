package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/cliveyg/poptape-admin/utils"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/gridfs"
	"go.mongodb.org/mongo-driver/mongo/options"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"io"
	"os"
	"os/exec"
	"time"
)

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

	tab := ""
	if table != "" {
		tab = "--table " + table
	}

	args := []string{
		"-h", creds.Host,
		"-U", creds.DBUsername,
		"-p", creds.DBPort,
		tab,
		dso,
		creds.DBName,
	}

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
			"saveId":     saveId.String(),
			"msId":       msId.String(),
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
		Valid:          true,
	}

	if err = a.SaveWithAutoVersion(&sr); err != nil {
		a.Log.Info().Msgf("Unable to insert save record [%s]", err.Error())
		return err
	}
	a.Log.Debug().Msg("Successfully inserted SaveRecord ✓")

	return nil
}

//-----------------------------------------------------------------------------

func (a *App) SaveWithAutoVersion(rec *SaveRecord) error {
	return a.DB.Transaction(func(tx *gorm.DB) error {
		var maxVersion int
		err := tx.Model(&SaveRecord{}).
			Where("microservice_id = ?", rec.MicroserviceId).
			Select("COALESCE(MAX(version), 0)").
			Clauses(clause.Locking{Strength: "UPDATE"}).
			Scan(&maxVersion).Error
		if err != nil {
			return err
		}
		rec.Version = maxVersion + 1
		return tx.Create(rec).Error
	})
}
