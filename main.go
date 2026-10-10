package main

import (
	"os"

	"ssmh/internal/app"
)

// Keep the root build usable without duplicating process or session ownership.
func main() { os.Exit(app.Execute()) }
