set GOROOT=%PROGRAMFILES%\Go
set GOARCH=amd64
set GOOS=windows
set CGO_ENABLED=0
set GO111MODULE=auto
del /F data\data.go
go-bindata -pkg data -o data/data.go panel/...
go build -ldflags="-s -w" -trimpath -o echo-server.exe