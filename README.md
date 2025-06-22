# poptape-admin

This microservice is for administering the overall poptape auction system. This means this api has direct access to the data in the other poptape microservices i.e. direct access to the postgres amd mongo databases and rabbitmq exchanges.

I could make this ms work by calling the other microservices and deleting/creating data that way but that would be pretty inefficient as the microservices are not designed for bulk additions and deletions. 

Obviously this type of api has an enormous amount of power and the ability to completely blwo away all the data in the system. It has it's own mini authentication and authorization process.