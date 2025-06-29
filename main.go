// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao-csi-provider/internal/clientcache"
	"github.com/openbao/openbao-csi-provider/internal/config"
	"github.com/openbao/openbao-csi-provider/internal/hmac"
	providerserver "github.com/openbao/openbao-csi-provider/internal/server"
	"github.com/openbao/openbao-csi-provider/internal/version"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	pb "sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"
)

const (
	namespaceFile = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

func main() {
	logger := hclog.Default()
	err := realMain(logger)
	if err != nil {
		logger.Error("Error running provider", "err", err)
		os.Exit(1)
	}
}

func realMain(logger hclog.Logger) error {
	flags := config.FlagsConfig{}
	flag.StringVar(&flags.Endpoint, "endpoint", "/tmp/openbao.sock", "Path to socket on which to listen for driver gRPC calls.")
	flag.BoolVar(&flags.Debug, "debug", false, "Sets log to debug level.")
	flag.BoolVar(&flags.Version, "version", false, "Prints the version information.")
	flag.StringVar(&flags.HealthAddr, "health-addr", ":8080", "Configure http listener for reporting health.")

	flag.StringVar(&flags.HMACSecretName, "hmac-secret-name", "openbao-csi-provider-hmac-key", "Configure the Kubernetes secret name that the provider creates to store an HMAC key for generating secret version hashes")

	flag.IntVar(&flags.CacheSize, "cache-size", 1000, "Set the maximum number of Openbao tokens that will be cached in-memory. One Openbao token will be stored for each pod on the same node that mounts secrets.")

	flag.StringVar(&flags.OpenbaoAddr, "openbao-addr", "", "Default address for connecting to Openbao. Can also be specified via the BAO_ADDR environment variable.")
	flag.StringVar(&flags.OpenbaoMount, "openbao-mount", "kubernetes", "Default Openbao mount path for authentication. Can refer to a Kubernetes or JWT auth mount.")
	flag.StringVar(&flags.OpenbaoNamespace, "openbao-namespace", "", "Default Openbao namespace for Openbao requests. Can also be specified via the BAO_NAMESPACE environment variable.")

	flag.StringVar(&flags.TLSCACertPath, "openbao-tls-ca-cert", "", "Path on disk to a single PEM-encoded CA certificate to trust for Openbao. Takes precendence over -openbao-tls-ca-directory. Can also be specified via the BAO_CACERT environment variable.")
	flag.StringVar(&flags.TLSCADirectory, "openbao-tls-ca-directory", "", "Path on disk to a directory of PEM-encoded CA certificates to trust for Openbao. Can also be specified via the BAO_CAPATH environment variable.")
	flag.StringVar(&flags.TLSServerName, "openbao-tls-server-name", "", "Name to use as the SNI host when connecting to Openbao via TLS. Can also be specified via the BAO_TLS_SERVER_NAME environment variable.")
	flag.StringVar(&flags.TLSClientCert, "openbao-tls-client-cert", "", "Path on disk to a PEM-encoded client certificate for mTLS communication with Openbao. If set, also requires -openbao-tls-client-key. Can also be specified via the BAO_CLIENT_CERT environment variable.")
	flag.StringVar(&flags.TLSClientKey, "openbao-tls-client-key", "", "Path on disk to a PEM-encoded client key for mTLS communication with Openbao. If set, also requires -openbao-tls-client-cert. Can also be specified via the BAO_CLIENT_KEY environment variable.")
	flag.BoolVar(&flags.TLSSkipVerify, "openbao-tls-skip-verify", false, "Disable verification of TLS certificates. Can also be specified via the BAO_SKIP_VERIFY environment variable.")
	flag.Parse()

	// set log level
	logger.SetLevel(hclog.Info)
	if flags.Debug {
		logger.SetLevel(hclog.Debug)
	}

	if flags.Version {
		v, err := version.GetVersion()
		if err != nil {
			return fmt.Errorf("failed to print version, err: %w", err)
		}
		// print the version and exit
		_, err = fmt.Println(v)
		return err
	}

	logger.Info("Creating new gRPC server")
	serverLogger := logger.Named("server")
	server := grpc.NewServer(
		grpc.UnaryInterceptor(func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
			startTime := time.Now()
			serverLogger.Info("Processing unary gRPC call", "grpc.method", info.FullMethod)
			resp, err := handler(ctx, req)
			serverLogger.Info("Finished unary gRPC call", "grpc.method", info.FullMethod, "grpc.time", time.Since(startTime), "grpc.code", status.Code(err), "err", err)
			return resp, err
		}),
	)

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-c
		logger.Info(fmt.Sprintf("Caught signal %s, shutting down", sig))
		server.GracefulStop()
	}()

	listener, err := listen(logger, flags.Endpoint)
	if err != nil {
		return err
	}
	defer func() {
		if err := listener.Close(); err != nil {
			logger.Error("Error closing listener: %v", err)
		}
	}()

	cfg, err := rest.InClusterConfig()
	if err != nil {
		return err
	}
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return err
	}

	namespace, err := os.ReadFile(namespaceFile)
	if err != nil {
		return fmt.Errorf("failed to read namespace from file: %w", err)
	}
	hmacSecretSpec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      flags.HMACSecretName,
			Namespace: string(namespace),
			// TODO: Configurable labels and annotations?
		},
		Immutable: ptr.To(true),
	}
	hmacGenerator := hmac.NewHMACGenerator(clientset, hmacSecretSpec)

	clientCache, err := clientcache.NewClientCache(serverLogger.Named("openbaoclient"), flags.CacheSize)
	if err != nil {
		return fmt.Errorf("failed to initialize the cache: %w", err)
	}

	srv := providerserver.NewServer(serverLogger, flags, clientset, hmacGenerator, clientCache)
	pb.RegisterCSIDriverProviderServer(server, srv)

	// Create health handler
	mux := http.NewServeMux()
	ms := http.Server{
		Addr:    flags.HealthAddr,
		Handler: mux,
	}
	defer func() {
		err := ms.Shutdown(context.Background())
		if err != nil {
			logger.Error("Error shutting down health handler", "err", err)
		}
	}()

	mux.HandleFunc("/health/ready", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Start health handler
	go func() {
		logger.Info("Starting health handler", "addr", flags.HealthAddr)
		if err := ms.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("Error with health handler", "error", err)
		}
	}()

	logger.Info("Starting gRPC server")
	err = server.Serve(listener)
	if err != nil {
		return fmt.Errorf("error running gRPC server: %w", err)
	}

	return nil
}

func listen(logger hclog.Logger, endpoint string) (net.Listener, error) {
	// Because the unix socket is created in a host volume (i.e. persistent
	// storage), it can persist from previous runs if the pod was not terminated
	// cleanly. Check if we need to clean up before creating a listener.
	_, err := os.Stat(endpoint)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to check for existence of unix socket: %w", err)
	} else if err == nil {
		logger.Info("Cleaning up pre-existing file at unix socket location", "endpoint", endpoint)
		err = os.Remove(endpoint)
		if err != nil {
			return nil, fmt.Errorf("failed to clean up pre-existing file at unix socket location: %w", err)
		}
	}

	logger.Info("Opening unix socket", "endpoint", endpoint)
	listener, err := net.Listen("unix", endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on unix socket at %s: %v", endpoint, err)
	}

	return listener, nil
}
