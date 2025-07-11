package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math"
	"math/big"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/pingcap/errors"
	"github.com/spf13/pflag"
	"go.etcd.io/etcd/clientv3"
	"go.etcd.io/etcd/pkg/transport"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/server/options"
	"k8s.io/apiserver/pkg/storage/storagebackend"
	"k8s.io/apiserver/pkg/util/compatibility"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/keyutil"
	"k8s.io/component-base/zpages/flagz"
	"k8s.io/klog"
	"k8s.io/kubernetes/cmd/kube-apiserver/app"
	"k8s.io/kubernetes/pkg/features"
)

var (
	bindAddress string

	ready atomic.Bool
)

func init() {
	flag.StringVar(&bindAddress, "bind-address", ":9177", "The IP address and port for the metrics and healthz server to serve on")

	flag.Usage = func() {
		fmt.Fprint(os.Stderr, "Usage: KASaaS [options]\n\n")
		flag.PrintDefaults()
	}
}

func main() {
	klog.InitFlags(nil)
	flag.Parse()

	flag.VisitAll(func(f *flag.Flag) {
		klog.Infof("FLAG: --%s=%q", f.Name, f.Value)
	})

	// trap Ctrl+C and call cancel on the context
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	// Enable signal handler
	signalCh := make(chan os.Signal, 2)
	defer func() {
		close(signalCh)
		cancel()
	}()
	signal.Notify(signalCh, os.Interrupt, unix.SIGINT)

	err := StartApiServer(ctx, customFlags, storageConfig)
	if err != nil {
		klog.Fatalf("could not start apiserver: %v", err)
	}

	select {
	case <-signalCh:
		klog.Infof("Exiting: received signal")
		cancel()
	case <-ctx.Done():
		klog.Infof("Exiting: context cancelled")
	}
}

func StartApiServer(ctx context.Context, customFlags []string, storageConfig *storagebackend.Config) error {

	fs := pflag.NewFlagSet("test", pflag.PanicOnError)

	featureGate := utilfeature.DefaultMutableFeatureGate.DeepCopy()
	effectiveVersion := compatibility.DefaultKubeEffectiveVersionForTest()
	if instanceOptions.BinaryVersion != "" {
		effectiveVersion = basecompatibility.NewEffectiveVersionFromString(instanceOptions.BinaryVersion, "", "")
	}
	effectiveVersion.SetEmulationVersion(featureGate.EmulationVersion())
	componentGlobalsRegistry := basecompatibility.NewComponentGlobalsRegistry()
	if err := componentGlobalsRegistry.Register(basecompatibility.DefaultKubeComponent, effectiveVersion, featureGate); err != nil {
		return err
	}

	s := options.NewServerRunOptions()
	// set up new instance of ComponentGlobalsRegistry instead of using the DefaultComponentGlobalsRegistry to avoid contention in parallel tests.
	s.Options.GenericServerRunOptions.ComponentGlobalsRegistry = componentGlobalsRegistry
	if instanceOptions.RequestTimeout > 0 {
		s.GenericServerRunOptions.RequestTimeout = instanceOptions.RequestTimeout
	}

	namedFlagSets := s.Flags()
	for _, f := range namedFlagSets.FlagSets {
		fs.AddFlagSet(f)
	}

	s.SecureServing.Listener, s.SecureServing.BindPort, err = createLocalhostListenerOnFreePort()
	if err != nil {
		return fmt.Errorf("failed to create listener: %v", err)
	}
	s.SecureServing.ServerCert.CertDirectory = result.TmpDir

	reqHeaderFromFlags := s.Authentication.RequestHeader
	if instanceOptions.EnableCertAuth {
		// set up default headers for request header auth
		reqHeaders := serveroptions.NewDelegatingAuthenticationOptions()
		s.Authentication.RequestHeader = &reqHeaders.RequestHeader

		var proxySigningKey *rsa.PrivateKey
		var proxySigningCert *x509.Certificate

		if instanceOptions.ProxyCA != nil {
			// use provided proxyCA
			proxySigningKey = instanceOptions.ProxyCA.ProxySigningKey
			proxySigningCert = instanceOptions.ProxyCA.ProxySigningCert

		} else {
			// create certificates for aggregation and client-cert auth
			proxySigningKey, err = testutil.NewPrivateKey()
			if err != nil {
				return err
			}
			proxySigningCert, err = cert.NewSelfSignedCACert(cert.Config{CommonName: "front-proxy-ca"}, proxySigningKey)
			if err != nil {
				return err
			}
		}
		proxyCACertFile := filepath.Join(s.SecureServing.ServerCert.CertDirectory, "proxy-ca.crt")
		if err := os.WriteFile(proxyCACertFile, testutil.EncodeCertPEM(proxySigningCert), 0644); err != nil {
			return err
		}
		s.Authentication.RequestHeader.ClientCAFile = proxyCACertFile

		// create private key
		signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}

		// make a client certificate for the api server - common name has to match one of our defined names above
		serial, err := rand.Int(rand.Reader, new(big.Int).SetInt64(math.MaxInt64-1))
		if err != nil {
			return err
		}
		serial = new(big.Int).Add(serial, big.NewInt(1))
		tenThousandHoursLater := time.Now().Add(10_000 * time.Hour)
		certTmpl := x509.Certificate{
			Subject: pkix.Name{
				CommonName: "misty",
			},
			SerialNumber: serial,
			NotBefore:    proxySigningCert.NotBefore,
			NotAfter:     tenThousandHoursLater,
			KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{
				x509.ExtKeyUsageClientAuth,
			},
			BasicConstraintsValid: true,
		}
		certDERBytes, err := x509.CreateCertificate(rand.Reader, &certTmpl, proxySigningCert, signer.Public(), proxySigningKey)
		if err != nil {
			return err
		}
		clientCrtOfAPIServer, err := x509.ParseCertificate(certDERBytes)
		if err != nil {
			return err
		}

		// write the cert to disk
		certificatePath := filepath.Join(s.SecureServing.ServerCert.CertDirectory, "misty-crt.crt")
		certBlock := pem.Block{
			Type:  "CERTIFICATE",
			Bytes: clientCrtOfAPIServer.Raw,
		}
		certBytes := pem.EncodeToMemory(&certBlock)
		if err := cert.WriteCert(certificatePath, certBytes); err != nil {
			return err
		}

		// write the key to disk
		privateKeyPath := filepath.Join(s.SecureServing.ServerCert.CertDirectory, "misty-crt.key")
		encodedPrivateKey, err := keyutil.MarshalPrivateKeyToPEM(signer)
		if err != nil {
			return err
		}
		if err := keyutil.WriteKey(privateKeyPath, encodedPrivateKey); err != nil {
			return err
		}

		s.ProxyClientKeyFile = filepath.Join(s.SecureServing.ServerCert.CertDirectory, "misty-crt.key")
		s.ProxyClientCertFile = filepath.Join(s.SecureServing.ServerCert.CertDirectory, "misty-crt.crt")

		clientSigningKey, err := testutil.NewPrivateKey()
		if err != nil {
			return err
		}
		clientSigningCert, err := cert.NewSelfSignedCACert(cert.Config{CommonName: "client-ca"}, clientSigningKey)
		if err != nil {
			return err
		}
		clientCACertFile := filepath.Join(s.SecureServing.ServerCert.CertDirectory, "client-ca.crt")
		if err := os.WriteFile(clientCACertFile, testutil.EncodeCertPEM(clientSigningCert), 0644); err != nil {
			return err
		}
		s.Authentication.ClientCert.ClientCA = clientCACertFile
	}

	s.SecureServing.ExternalAddress = s.SecureServing.Listener.Addr().(*net.TCPAddr).IP // use listener addr although it is a loopback device

	pkgPath, err := pkgPath(t)
	if err != nil {
		return err
	}
	s.SecureServing.ServerCert.FixtureDirectory = filepath.Join(pkgPath, "testdata")

	s.ServiceClusterIPRanges = "10.0.0.0/16"
	s.Etcd.StorageConfig = *storageConfig

	if err := fs.Parse(customFlags); err != nil {
		return err
	}
	if utilfeature.DefaultFeatureGate.Enabled(zpagesfeatures.ComponentFlagz) {
		s.Flagz = flagz.NamedFlagSetsReader{FlagSets: namedFlagSets}
	}

	// the RequestHeader options pointer gets replaced in the case of EnableCertAuth override
	// and so flags are connected to a struct that no longer appears in the ServerOptions struct
	// we're using.
	// We still want to make it possible to configure the headers config for the RequestHeader authenticator.
	if usernameHeaders := reqHeaderFromFlags.UsernameHeaders; len(usernameHeaders) > 0 {
		s.Authentication.RequestHeader.UsernameHeaders = usernameHeaders
	}
	if uidHeaders := reqHeaderFromFlags.UIDHeaders; len(uidHeaders) > 0 {
		s.Authentication.RequestHeader.UIDHeaders = uidHeaders
	}
	if groupHeaders := reqHeaderFromFlags.GroupHeaders; len(groupHeaders) > 0 {
		s.Authentication.RequestHeader.GroupHeaders = groupHeaders
	}
	if extraHeaders := reqHeaderFromFlags.ExtraHeaderPrefixes; len(extraHeaders) > 0 {
		s.Authentication.RequestHeader.ExtraHeaderPrefixes = extraHeaders
	}

	if err := componentGlobalsRegistry.Set(); err != nil {
		return fmt.Errorf("%w\nIf you are using SetFeatureGate*DuringTest, try using --emulated-version and --feature-gates flags instead", err)
	}
	// If the local ComponentGlobalsRegistry is changed by the flags,
	// we need to copy the new feature values back to the DefaultFeatureGate because most feature checks still use the DefaultFeatureGate.
	// We cannot directly use DefaultFeatureGate in ComponentGlobalsRegistry because the changes done by ComponentGlobalsRegistry.Set() will not be undone at the end of the test.
	if !featureGate.EmulationVersion().EqualTo(utilfeature.DefaultMutableFeatureGate.EmulationVersion()) {
		featuregatetesting.SetFeatureGateEmulationVersionDuringTest(t, utilfeature.DefaultMutableFeatureGate, effectiveVersion.EmulationVersion())
	}
	for f := range utilfeature.DefaultMutableFeatureGate.GetAll() {
		if featureGate.Enabled(f) != utilfeature.DefaultFeatureGate.Enabled(f) {
			featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, f, featureGate.Enabled(f))
		}
	}
	utilfeature.DefaultMutableFeatureGate.AddMetrics()

	if instanceOptions.EnableCertAuth {
		if featureGate.Enabled(features.UnknownVersionInteroperabilityProxy) {
			// TODO: set up a general clean up for testserver
			if clientgotransport.DialerStopCh == wait.NeverStop {
				ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
				t.Cleanup(cancel)
				clientgotransport.DialerStopCh = ctx.Done()
			}
			s.PeerCAFile = filepath.Join(s.SecureServing.ServerCert.CertDirectory, s.SecureServing.ServerCert.PairName+".crt")
		}
	}

	saSigningKeyFile, err := os.CreateTemp("/tmp", "insecure_test_key")
	if err != nil {
		t.Fatalf("create temp file failed: %v", err)
	}
	defer os.RemoveAll(saSigningKeyFile.Name())
	if err = os.WriteFile(saSigningKeyFile.Name(), []byte(ecdsaPrivateKey), 0666); err != nil {
		t.Fatalf("write file %s failed: %v", saSigningKeyFile.Name(), err)
	}
	s.ServiceAccountSigningKeyFile = saSigningKeyFile.Name()
	s.Authentication.ServiceAccounts.Issuers = []string{"https://foo.bar.example.com"}
	s.Authentication.ServiceAccounts.KeyFiles = []string{saSigningKeyFile.Name()}

	completedOptions, err := s.Complete(ctx)
	if err != nil {
		return fmt.Errorf("failed to set default ServerRunOptions: %v", err)
	}

	if errs := completedOptions.Validate(); len(errs) != 0 {
		return fmt.Errorf("failed to validate ServerRunOptions: %v", utilerrors.NewAggregate(errs))
	}

	t.Logf("runtime-config=%v", completedOptions.APIEnablement.RuntimeConfig)
	t.Logf("Starting kube-apiserver on port %d...", s.SecureServing.BindPort)

	config, err := app.NewConfig(completedOptions)
	if err != nil {
		return err
	}
	completed, err := config.Complete()
	if err != nil {
		return err
	}
	server, err := app.CreateServerChain(completed)
	if err != nil {
		return fmt.Errorf("failed to create server chain: %v", err)
	}
	if instanceOptions.StorageVersionWrapFunc != nil {
		server.GenericAPIServer.StorageVersionManager = instanceOptions.StorageVersionWrapFunc(server.GenericAPIServer.StorageVersionManager)
	}

	errCh = make(chan error)
	go func() {
		defer close(errCh)
		prepared, err := server.PrepareRun()
		if err != nil {
			errCh <- err
		} else if err := prepared.Run(ctx); err != nil {
			errCh <- err
		}
	}()

	client, err := kubernetes.NewForConfig(server.GenericAPIServer.LoopbackClientConfig)
	if err != nil {
		return fmt.Errorf("failed to create a client: %v", err)
	}

	if !instanceOptions.SkipHealthzCheck {
		t.Logf("Waiting for /healthz to be ok...")

		// wait until healthz endpoint returns ok
		err = wait.Poll(100*time.Millisecond, time.Minute, func() (bool, error) {
			select {
			case err := <-errCh:
				return false, err
			default:
			}

			req := client.CoreV1().RESTClient().Get().AbsPath("/healthz")
			// The storage version bootstrap test wraps the storage version post-start
			// hook, so the hook won't become health when the server bootstraps
			if instanceOptions.StorageVersionWrapFunc != nil {
				// We hardcode the param instead of having a new instanceOptions field
				// to avoid confusing users with more options.
				storageVersionCheck := fmt.Sprintf("poststarthook/%s", apiserver.StorageVersionPostStartHookName)
				req.Param("exclude", storageVersionCheck)
			}
			result := req.Do(context.TODO())
			status := 0
			result.StatusCode(&status)
			if status == 200 {
				return true, nil
			}
			return false, nil
		})
		if err != nil {
			return fmt.Errorf("failed to wait for /healthz to return ok: %v", err)
		}
	}

	// wait until default namespace is created
	err = wait.Poll(100*time.Millisecond, 30*time.Second, func() (bool, error) {
		select {
		case err := <-errCh:
			return false, err
		default:
		}

		if _, err := client.CoreV1().Namespaces().Get(context.TODO(), "default", metav1.GetOptions{}); err != nil {
			if !errors.IsNotFound(err) {
				t.Logf("Unable to get default namespace: %v", err)
			}
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		return fmt.Errorf("failed to wait for default namespace to be created: %v", err)
	}

	etcdClient, _, err := GetEtcdClients(storageConfig.Transport)
	if err != nil {
		return fmt.Errorf("create etcd client: %w", err)
	}

	return nil
}

// GetEtcdClients returns an initialized etcd clientv3.Client and clientv3.KV.
func GetEtcdClients(config storagebackend.TransportConfig) (*clientv3.Client, clientv3.KV, error) {
	// clientv3.New ignores an invalid TLS config for http://, but not for unix:// (https://github.com/etcd-io/etcd/blob/5a8fba466087686fc15815f5bc041fb7eb1f23ea/client/v3/internal/endpoint/endpoint.go#L61-L66).
	// To support unix://, we must not set Config.TLS unless we really have
	// transport security.
	var tlsConfig *tls.Config
	if config.CertFile != "" ||
		config.KeyFile != "" ||
		config.TrustedCAFile != "" {
		tlsInfo := transport.TLSInfo{
			CertFile:      config.CertFile,
			KeyFile:       config.KeyFile,
			TrustedCAFile: config.TrustedCAFile,
		}

		var err error
		tlsConfig, err = tlsInfo.ClientConfig()
		if err != nil {
			return nil, nil, err
		}
	}

	cfg := clientv3.Config{
		Endpoints:   config.ServerList,
		DialTimeout: 20 * time.Second,
		DialOptions: []grpc.DialOption{
			grpc.WithBlock(), // block until the underlying connection is up
		},
		TLS: tlsConfig,
	}

	c, err := clientv3.New(cfg)
	if err != nil {
		return nil, nil, err
	}

	return c, clientv3.NewKV(c), nil
}
