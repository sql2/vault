package main

import (
	"log"
	"os"

	"github.com/hashicorp/vault/api"
	"github.com/sql2/vault/plugins/database/proxysql"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:])

	err := proxysql.Run(apiClientMeta.GetTLSConfig())
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
}
