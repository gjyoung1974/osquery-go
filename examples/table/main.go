package main

import (
	"context"
	"flag"
	"github.com/kolide/osquery-go"
	"github.com/kolide/osquery-go/plugin/table"
	"github.com/prometheus/procfs"
	"log"
	"time"
)

var (
	socket   = flag.String("socket", "", "Path to the extensions UNIX domain socket")
	timeout  = flag.Int("timeout", 3, "Seconds to wait for autoloaded extensions")
	interval = flag.Int("interval", 3, "Seconds delay between connectivity checks")
)

func main() {
	flag.Parse()
	if *socket == "" {
		log.Fatalln("Missing required --socket argument")
	}
	serverTimeout := osquery.ServerTimeout(
		time.Second * time.Duration(*timeout),
	)
	serverPingInterval := osquery.ServerPingInterval(
		time.Second * time.Duration(*interval),
	)

	server, err := osquery.NewExtensionManagerServer(
		"example_extension",
		*socket,
		serverTimeout,
		serverPingInterval,
	)

	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}
	server.RegisterPlugin(table.NewPlugin("kubernetes_pods", KubernetesPodsColumns(), KubernetesPodsGenerate))
	server.RegisterPlugin(table.NewPlugin("kubernetes_containers", KubernetesContainersColumns(), KubernetesContainersGenerate))
	if err := server.Run(); err != nil {
		log.Fatal(err)
	}
}

func foo() {
	fs, _ := procfs.NewFS("/host/procfs")
	fs.AllProcs()
}

func getHostProcessInfo() string {
	log.Println("Get Host process info")
	fs, err := procfs.NewFS("/host/procfs")
	if err != nil {
		// return nil;
	}
	log.Println(fs.CPUInfo())
	return "stuff"
}

func KubernetesPodsColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("uid"),
		table.TextColumn("name"),
		table.TextColumn("namespace"),
		table.IntegerColumn("priority"),
		table.TextColumn("node"),
		table.TextColumn("start_time"),
		table.TextColumn("labels"),
		table.TextColumn("annotations"),
		table.TextColumn("status"),
		table.TextColumn("ip"),
		table.TextColumn("controlled_by"),
		table.TextColumn("owner_uid"),
		table.TextColumn("qos_class"),
	}
}

func KubernetesContainersColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("id"),
		table.TextColumn("name"),
		table.TextColumn("pod_uid"),
		table.TextColumn("pod_name"),
		table.TextColumn("namespace"),
		table.TextColumn("image"),
		table.TextColumn("image_id"),
		table.TextColumn("state"),
		table.IntegerColumn("ready"),
		table.TextColumn("started_at"),
		// table.TextColumn("env_variables"),
	}
}

func KubernetesPodsGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	return []map[string]string{
		{
			"name":    "foo",
			"namespace": "team-security",
			"node":  "localhost",
		},
	}, nil
}

func KubernetesContainersGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	return []map[string]string{
		{
			"text":    "hello world",
			"integer": "123",
			"big_int": "-1234567890",
			"double":  "3.14159",
		},
	}, nil
}
