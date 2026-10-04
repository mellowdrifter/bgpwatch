module github.com/mellowdrifter/bgpwatch

go 1.26.2

require (
	github.com/golang/protobuf v1.5.4
	github.com/google/go-cmp v0.7.0
	github.com/mellowdrifter/bogons v1.2.0
	github.com/mellowdrifter/routing_table v0.0.0-20260506014832-4c4b423db1ab
	github.com/osrg/gobgp/v3 v3.37.0
	github.com/stretchr/testify v1.11.1
	golang.org/x/sys v0.48.0
	google.golang.org/grpc v1.81.0
	google.golang.org/protobuf v1.36.11
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dgryski/go-farm v0.0.0-20240924180020-3414d57e47da // indirect
	github.com/eapache/channels v1.1.0 // indirect
	github.com/eapache/queue v1.1.0 // indirect
	github.com/fsnotify/fsnotify v1.10.1 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/k-sone/critbitgo v1.4.0 // indirect
	github.com/pelletier/go-toml/v2 v2.3.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/sagikazarmark/locafero v0.12.0 // indirect
	github.com/sirupsen/logrus v1.9.4 // indirect
	github.com/spf13/afero v1.15.0 // indirect
	github.com/spf13/cast v1.10.0 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/spf13/viper v1.21.0 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/vishvananda/netlink v1.3.1 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	golang.org/x/net v0.59.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260504160031-60b97b32f348 // indirect
	gopkg.in/check.v1 v1.0.0-20190902080502-41f04d3bba15 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/mellowdrifter/routing_table => ../routing_table
