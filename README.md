# AuthServer
Authentication Server developed as part of ROS Secure or ROSS project.

The AuthServer authenticates nodes and manages key distribution among nodes in a ROSS system.

[MudBoxer](https://github.com/srinskit/MudBoxer), on initialization, starts a mutually-authenticated SSL connection with the AuthServer. When a node registers with the ROS Master to publish/subscribe to a topic, the MudBoxer requests the AuthServer for the common key used to encrypt/decrypt messages under that topic.
