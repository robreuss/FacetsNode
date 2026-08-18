package main

import (
	"github.com/robreuss/FacetsNode/internal/config"
	"github.com/robreuss/FacetsNode/internal/serverapp"
)

func main() {
	serverapp.Main(config.DeviceSync)
}
