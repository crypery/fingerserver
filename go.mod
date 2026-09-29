module example.com/echo-server

go 1.24.9

require (
	data v0.0.0-00010101000000-000000000000
	github.com/dreadl0ck/tlsx v1.0.3
	github.com/google/gopacket v1.1.19
	github.com/refraction-networking/utls v1.8.1
	github.com/wi1dcard/fingerproxy v1.2.3
	ip2location v0.0.0-00010101000000-000000000000
	useragent v0.0.0-00010101000000-000000000000
)

require (
	github.com/andybalholm/brotli v1.2.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/matttproud/golang_protobuf_extensions/v2 v2.0.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/prometheus/client_golang v1.23.2 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.67.1 // indirect
	github.com/prometheus/procfs v0.17.0 // indirect
	go.yaml.in/yaml/v2 v2.4.3 // indirect
	golang.org/x/crypto v0.43.0 // indirect
	golang.org/x/net v0.46.0 // indirect
	golang.org/x/sys v0.37.0 // indirect
	golang.org/x/text v0.30.0 // indirect
	google.golang.org/protobuf v1.36.10 // indirect
	uint128 v0.0.0-00010101000000-000000000000 // indirect
)

replace (
	data => ./data
	ip2location => ./ip2location
	uint128 => ./ip2location/uint128
	useragent => ./useragent

)
