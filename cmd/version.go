package cmd

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const version = "0.0.1"

func init() {
	var versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Get ocpup version",
		Run: func(cmd *cobra.Command, args []string) {
			log.Infof("ocpup version: %s", version)
		},
	}
	rootCmd.AddCommand(versionCmd)
}
