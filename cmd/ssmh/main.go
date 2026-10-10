package main

import (
	"os"

	"ssmh/internal/app"
)

func main() { os.Exit(execute()) }

func execute() int { return app.Execute() }
