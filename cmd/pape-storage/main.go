package main

import (
	"flag"
	"log"

	"pape-storage/internal/config"
	"pape-storage/internal/server"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to the YAML configuration file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	if err := server.Run(cfg); err != nil {
		log.Fatal(err)
	}
}
