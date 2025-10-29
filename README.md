![All tests pass](https://github.com/cliveyg/poptape-admin/actions/workflows/api-tests.yml/badge.svg) ![Unit tests passed](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/cliveyg/598362f87ae7935640177e455be6de99/raw/8e953500098f2feca0cf23f88c3b454372fcfade/total-go-tests.json&label=Total%20tests) ![Total test coverage](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/cliveyg/598362f87ae7935640177e455be6de99/raw/8e953500098f2feca0cf23f88c3b454372fcfade/total-lcov-coverage.json&label=Total%20test%20coverage) 

<!-- ![Unit tests passed](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/cliveyg/4d4c56866a2de0d9f504b5cf5916fb1b/raw/169979535ec8f58f69b6fb2cb4e4693bcbdde9bc/unit-go-tests.json&label=Unit%20Tests) ![Unit test coverage](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/cliveyg/4d4c56866a2de0d9f504b5cf5916fb1b/raw/169979535ec8f58f69b6fb2cb4e4693bcbdde9bc/unit-lcov-coverage.json&label=Unit%20Test%20Coverage) ![Integration tests passed](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/cliveyg/b1a44fe2133feeba581e388383eb76f9/raw/f907acdfd757587974d66f752bbc32f66602538a/int-go-tests.json&label=Integration%20Tests) ![Integration test coverage](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/cliveyg/b1a44fe2133feeba581e388383eb76f9/raw/f907acdfd757587974d66f752bbc32f66602538a/int-lcov-coverage.json&label=Integration%20Test%20Coverage) -->

# poptape-admin

This microservice is for administering the overall poptape auction system. i.e. For loading and unloading data into the system. This means this api has direct access to the data in the other poptape microservices i.e. direct access to the Postgres and Mongo databases and rabbitmq exchanges.

I could make this microservice work by calling the other microservices and deleting/creating data that way but on the whole this method is inefficient as the microservices are not designed for bulk additions and deletions. 

However some actions such as creating a new user will use such calls. For example creating a new user will call the *authy* api rather than using direct access as this action calls other api's including external ones and mirroring this process here makes little sense.

Obviously this type of api has an enormous amount of power and the ability to completely blow away all the data in the system. It has its own mini authentication and authorization process.

### Overall Backup Process
This _poptape-admin_ microservice uses both SQL and NoSQL databases. The NoSQL db is Mongo, configured to use GridFS, to store the output of any backups. 
All backup data is streamed directly from the outputs of the save tools/binaries into the Mongo db and when restoring, the data is streamed from the GridFS Mongo instance direct to stdin of the tools.
This is in case the save and restore data become large and don't fit into memory. GridFS was chosen as this can cope with the possibly large files that can be created from backups.

Data/metadata about these saves/backups is stored in the _poptape-admin_ Postgres db.

### Postgres Based Microservices
All data and schema for Postgres based microservices is backed up by using the external _pg_dump_ binary/cmd and is restored also using an external binary/cmd: _psql_ 

### Mongo Based Microservices
All data for Mongo based microservices is backed up using the external _mongodump_ binary/cmd and restored using the _mongorestore_ binary/cmd.

### JWT 

Sessions are managed by using JWT's. JWT's are set with a short expiry time (currently 15mins) and refreshed on the server side with every call - in the PROD environment; In DEV the expiry time is set to 24h. We will look at adjusting this mechanism in the future. The client side application will have to deal with storing and swapping the new JWT for the old one.

### Client Side Application

In tandem with this microservice a client side application should be written to help manage the system. Currently we are using the [Bruno](https://docs.usebruno.com/) open source api client to make calls to this microservice.

### TODO:
* Most of it!
* Lot and lots of tests