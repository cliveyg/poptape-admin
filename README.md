# poptape-admin

This microservice is for administering the overall poptape auction system. i.e. For loading and unloading data into the system. This means this api has direct access to the data in the other poptape microservices i.e. direct access to the postgres amd mongo databases and rabbitmq exchanges.

I could make this microservice work by calling the other microservices and deleting/creating data that way but on the whole this method is inefficient as the microservices are not designed for bulk additions and deletions. 

However some actions such as creating a new user will use such calls. For example creating a new user will call the *authy* api rather than using direct access as this action calls other api's including external ones and mirroring this process here makes little sense.

Obviously this type of api has an enormous amount of power and the ability to completely blow away all the data in the system. It has its own mini authentication and authorization process.

### JWT 

Sessions are managed by using JWT's. JWT's are set with a short expiry time (currently 15mins) and refreshed on the server side with every call - in the PROD environment; In DEV the expiry time is set to 24h. We will look at adjusting this mechanism in the future. The client side application will have to deal with storing and swapping the new JWT for the old one.

### Client Side Application

In tandem with this microservice a client side application should be written to help manage the system. Currently we are using the [Bruno](https://docs.usebruno.com/) open source api client to make calls to this microservice.

### TODO:
* Almost all of it!
* Tests