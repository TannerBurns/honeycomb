package main

import (
	"encoding/json"
	"fmt"
	"os"

	"./models"
)

func main() {
	if len(os.Args) < 1 {
		fmt.Println("No path found as argument")
		return
	}
	rh, err := models.NewRegistryHive(os.Args[1])
	if err != nil {
		fmt.Println(err)
	}
	rh.Parse()
	d, err := json.MarshalIndent(rh, "", "    ")
	fmt.Println(string(d))
}
