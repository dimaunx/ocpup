package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/dustin/go-humanize"
	"github.com/mholt/archiver"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
	"io"
	"io/ioutil"
	corev1 "k8s.io/api/core/v1"
	extensionsv1beta1 "k8s.io/api/extensions/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"text/template"
	"time"
)

var Username string

type KubeConfig struct {
	APIVersion string `yaml:"apiVersion"`
	Clusters   []struct {
		Cluster struct {
			CertificateAuthorityData string `yaml:"certificate-authority-data"`
			Server                   string `yaml:"server"`
		} `yaml:"cluster"`
		Name string `yaml:"name"`
	} `yaml:"clusters"`
	Contexts []struct {
		Context struct {
			Cluster string `yaml:"cluster"`
			User    string `yaml:"user"`
		} `yaml:"context"`
		Name string `yaml:"name"`
	} `yaml:"contexts"`
	CurrentContext string `yaml:"current-context"`
	Kind           string `yaml:"kind"`
	Preferences    struct {
	} `yaml:"preferences"`
	Users []struct {
		Name string `yaml:"name"`
		User struct {
			ClientCertificateData string `yaml:"client-certificate-data"`
			ClientKeyData         string `yaml:"client-key-data"`
		} `yaml:"user"`
	} `yaml:"users"`
}

type ClusterData struct {
	ClusterName    string `yaml:"clusterName"`
	SubmarinerType string `yaml:"submarinerType"`
	ClusterType    string `yaml:"clusterType"`
	VpcCidr        string `yaml:"vpcCidr"`
	PodCidr        string `yaml:"podCidr"`
	SvcCidr        string `yaml:"svcCidr"`
	NumMasters     int    `yaml:"numMasters"`
	NumWorkers     int    `yaml:"numWorkers"`
	DNSDomain      string `yaml:"dnsDomain"`
	Platform       struct {
		Name            string `yaml:"name"`
		Region          string `yaml:"region"`
		LbFloatingIP    string `yaml:"lbFloatingIP"`
		ExternalNetwork string `yaml:"externalNetwork,omitempty"`
		ComputeFlavor   string `yaml:"computeFlavor,omitempty"`
	} `yaml:"platform"`
}

type ClustersConfig struct {
	Clusters []ClusterData
}

type HelmData struct {
	HelmRepo struct {
		URL  string `yaml:"url"`
		Name string `yaml:"name"`
	} `yaml:"helmRepo"`
	Broker struct {
		Namespace string `yaml:"namespace"`
	} `yaml:"broker"`
	Engine struct {
		Namespace string `yaml:"namespace"`
		Image     struct {
			Repository string `yaml:"repository"`
			Tag        string `yaml:"tag"`
		} `yaml:"image"`
	} `yaml:"engine"`
	RouteAgent struct {
		Namespace string `yaml:"namespace"`
		Image     struct {
			Repository string `yaml:"repository"`
			Tag        string `yaml:"tag"`
		} `yaml:"image"`
	} `yaml:"routeAgent"`
}

type AuthData struct {
	PullSecret string `yaml:"pullSecret"`
	SSHKey     string `yaml:"sshKey"`
	OpenStack  struct {
		AuthURL        string `yaml:"authUrl"`
		Username       string `yaml:"userName"`
		Password       string `yaml:"password"`
		ProjectID      string `yaml:"projectId"`
		ProjectName    string `yaml:"projectName"`
		UserDomainName string `yaml:"userDomainName"`
	} `yaml:"openstack"`
}

type OpenshiftData struct {
	Version string `yaml:"version"`
}

type WriteCounter struct {
	Total    uint64
	FileName string
}

func (wc *WriteCounter) Write(p []byte) (int, error) {
	n := len(p)
	wc.Total += uint64(n)
	wc.PrintProgress()
	return n, nil
}

func (wc WriteCounter) PrintProgress() {
	// Clear the line by using a character return to go back to the start and remove
	// the remaining characters by filling it with spaces
	fmt.Printf("\r%s", strings.Repeat(" ", 180))

	// Return again and print current status of download
	// We use the humanize package to print the bytes in a meaningful way (e.g. 10 MB)
	fmt.Printf("\rDownloading %s... %s complete", wc.FileName, humanize.Bytes(wc.Total))
}

func diff(lhsSlice, rhsSlice []string) (lhsOnly []string, rhsOnly []string) {
	return singleDiff(lhsSlice, rhsSlice), singleDiff(rhsSlice, lhsSlice)
}

func singleDiff(lhsSlice, rhsSlice []string) (lhsOnly []string) {
	for _, lhs := range lhsSlice {
		found := false
		for _, rhs := range rhsSlice {
			if lhs == rhs {
				found = true
				break
			}
		}

		if !found {
			lhsOnly = append(lhsOnly, lhs)
		}
	}

	return lhsOnly
}

//Download tools
func DownloadFile(url string, filepath string, filename string) error {

	// Create the file, but give it a tmp file extension, this means we won't overwrite a
	// file until it's downloaded, but we'll remove the tmp extension once downloaded.
	out, err := os.Create(filepath + ".tmp")
	if err != nil {
		return err
	}
	defer out.Close()

	// Get the data
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Create our progress reporter and pass it to be used alongside our writer
	counter := &WriteCounter{FileName: filename}
	_, err = io.Copy(out, io.TeeReader(resp.Body, counter))
	if err != nil {
		return err
	}

	// The progress use the same line so print a new line once it's finished downloading
	fmt.Print("\n")

	err = os.Rename(filepath+".tmp", filepath)
	if err != nil {
		return err
	}

	return nil
}

//Run terraform init
func TerraformInit() error {
	log.Info("Running Terraform init...")
	cmd := exec.Command("./bin/terraform", "init")
	buf := &bytes.Buffer{}
	cmd.Stdout = buf
	cmd.Stderr = buf

	err := cmd.Start()
	if err != nil {
		return errors.Wrapf(err, "Error starting terraform init: %s %s", buf.String())
	}

	err = cmd.Wait()
	if err != nil {
		return errors.Wrapf(err, "Error waiting for terraform init: %s %s", buf.String())
	}
	log.Debug(buf.String())
	return nil
}

//Get dependencies required for multi cluster setup
func GetDependencies(v *OpenshiftData) error {
	if runtime.GOOS == "linux" {
		log.Debugf("Hello from linux.")
	}

	shortVersion := strings.Split(v.Version, "-")[0]
	release := strings.Join(strings.Split(strings.Split(v.Version, "-")[0], ".")[:2], ".")
	log.Infof("Getting required tools OCP version: %s, release: %s.", v.Version, release)

	currentDir, _ := os.Getwd()
	binDir := filepath.Join(currentDir, "bin")
	tmpDir := filepath.Join(currentDir, "tmp")
	_ = os.MkdirAll(binDir, os.ModePerm)
	_ = os.MkdirAll(tmpDir, os.ModePerm)

	if _, err := os.Stat("./bin/helm"); os.IsNotExist(err) {
		err = DownloadFile("https://storage.googleapis.com/kubernetes-helm/helm-v2.14.1-linux-amd64.tar.gz", "./tmp/helm.tar.gz", "helm")
		if err != nil {
			return err
		}
		_ = os.Remove("./tmp/linux-amd64")
		err = archiver.Extract("./tmp/helm.tar.gz", "linux-amd64/helm", "./tmp")
		if err != nil {
			return err
		}

		oldLocation := "./tmp/linux-amd64/helm"
		newLocation := "./bin/helm"
		err = os.Rename(oldLocation, newLocation)
		if err != nil {
			return err
		}
	} else {
		log.Debugf("Helm already exists.")
	}

	if _, err := os.Stat("./bin/terraform"); os.IsNotExist(err) {
		err = DownloadFile("https://releases.hashicorp.com/terraform/0.12.9/terraform_0.12.9_linux_amd64.zip", "./tmp/terraform.zip", "terraform")
		if err != nil {
			return err
		}

		z := archiver.Zip{
			ImplicitTopLevelFolder: false,
			OverwriteExisting:      true,
			MkdirAll:               false,
		}

		err = z.Extract("./tmp/terraform.zip", "terraform", "./bin")
		if err != nil {
			return err
		}
	} else {
		log.Debugf("Terraform exists.")
	}

	if _, err := os.Stat("./bin/openshift-install"); os.IsNotExist(err) {
		err := GetOcpTools(v.Version)
		if err != nil {
			return err
		}
	} else {
		cmdName := "./bin/openshift-install"
		cmdArgs := []string{"version"}

		cmd := exec.Command(cmdName, cmdArgs...)
		buf := &bytes.Buffer{}
		cmd.Stdout = buf
		cmd.Stderr = buf

		err := cmd.Start()
		if err != nil {
			return errors.Wrapf(err, "Error starting openshift-install: %s\n%s", buf.String())
		}

		err = cmd.Wait()
		if err != nil {
			return errors.Wrapf(err, "Error waiting openshift-install: %s\n%s", buf.String())
		}

		// TODO issue with 4.2 as openshift-install version command does not contain the 4.2 version forces tool to be re downloaded each time.
		if strings.Contains(buf.String(), shortVersion) {
			log.Debugf("OCP tools with version %s already exist.", shortVersion)
		} else {
			err := GetOcpTools(v.Version)
			if err != nil {
				return err
			}
		}
	}
	_ = os.RemoveAll(filepath.Join(currentDir, "tmp"))
	return nil
}

//Get openshift install and client binaries
func GetOcpTools(version string) error {
	url := "https://mirror.openshift.com/pub/openshift-v4/clients/ocp-dev-preview" + "/" + version + "/openshift-install-linux-" + version + ".tar.gz"
	err := DownloadFile(url, "./tmp/openshift-install-linux-"+version+".tar.gz", "openshift-install")
	if err != nil {
		return err
	}

	_ = os.Remove("./bin/openshift-install")
	source := "./tmp/openshift-install-linux-" + version + ".tar.gz"
	err = archiver.Extract(source, "openshift-install", "./bin")
	if err != nil {
		return err
	}

	url = "https://mirror.openshift.com/pub/openshift-v4/clients/ocp-dev-preview" + "/" + version + "/openshift-client-linux-" + version + ".tar.gz"
	err = DownloadFile(url, "./tmp/openshift-client-linux-"+version+".tar.gz", "oc")
	if err != nil {
		return err
	}

	_ = os.Remove("./bin/oc")
	source = "./tmp/openshift-client-linux-" + version + ".tar.gz"
	err = archiver.Extract(source, "oc", "./bin")
	if err != nil {
		return err
	}
	return nil
}

//Copy existing kubeconfig files with required changes
func ModifyKubeConfigFiles(cls []ClusterData) {
	log.Info("Modifying kubeconfig files.")

	var kubeconf KubeConfig

	for _, cl := range cls {
		currentDir, _ := os.Getwd()
		kubeFile := filepath.Join(currentDir, ".config", cl.ClusterName, "auth", "kubeconfig")
		newKubeFile := filepath.Join(currentDir, ".config", cl.ClusterName, "auth", "kubeconfig-dev")
		kubefile, err := ioutil.ReadFile(kubeFile)
		if err != nil {
			log.Error(err)
		}

		err = yaml.Unmarshal(kubefile, &kubeconf)
		if err != nil {
			log.Error(err)
		}

		kubeconf.CurrentContext = cl.ClusterName
		kubeconf.Contexts[0].Name = cl.ClusterName
		kubeconf.Contexts[0].Context.Cluster = cl.ClusterName
		kubeconf.Contexts[0].Context.User = cl.ClusterName
		kubeconf.Clusters[0].Name = cl.ClusterName
		kubeconf.Users[0].Name = cl.ClusterName

		d, err := yaml.Marshal(&kubeconf)
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		err = ioutil.WriteFile(newKubeFile, d, 0644)
		if err != nil {
			log.Error(err)
		}
		log.Debugf("Modifying %s", kubeFile)
	}
	log.Infof("✔ Kubeconfigs: export KUBECONFIG=$(echo $(git rev-parse --show-toplevel)/.config/cl{1..%v}/auth/kubeconfig-dev | sed 's/ /:/g')", len(cls))
}

func GenerateConfigs(cl ClusterData, auth *AuthData) error {
	return GenerateConfigDirs(cl, auth)
}

//Generate config dirs
func GenerateConfigDirs(cl ClusterData, auth *AuthData) error {
	currentDir, _ := os.Getwd()

	configDir := filepath.Join(currentDir, ".config", cl.ClusterName)
	err := os.MkdirAll(configDir, os.ModePerm)
	if err != nil {
		return errors.Wrapf(err, "error creating config dir %s", cl.ClusterName)
	}

	log.Debugf("ClustersConfig directories for %s created.", cl.ClusterName)

	return GenerateConfigFiles(cl, auth)
}

//Generate config files
func GenerateConfigFiles(cl ClusterData, auth *AuthData) error {

	currentDir, _ := os.Getwd()

	c, err := user.Current()
	if err != nil {
		return err
	}

	t, err := template.ParseFiles(filepath.Join(currentDir, "tpl", "install-config.yaml"))
	if err != nil {
		return err
	}

	tc, err := template.ParseFiles(filepath.Join(currentDir, "tpl", "clouds.yaml"))
	if err != nil {
		return err
	}

	if _, err := os.Stat(filepath.Join(currentDir, ".config", cl.ClusterName, "metadata.json")); os.IsNotExist(err) {
		configFile := filepath.Join(currentDir, ".config", cl.ClusterName, "install-config.yaml")
		f, err := os.Create(configFile)
		if err != nil {
			return errors.Wrapf(err, "creating config file %s", cl.ClusterName)
		}

		type combined struct {
			ClusterData
			AuthData
		}

		switch cl.Platform.Name {
		case "openstack":
			cloudsFile := filepath.Join(currentDir, "clouds.yaml")
			cf, err := os.Create(cloudsFile)
			if err != nil {
				return errors.Wrapf(err, "creating clouds.yaml file %s", cl.ClusterName)
			}

			err = tc.Execute(cf, combined{cl, *auth})
			if err != nil {
				return errors.Wrapf(err, "creating config file %s", cl.ClusterName)
			}

			if err := cf.Close(); err != nil {
				return err
			}

			cl.Platform.LbFloatingIP = cl.CreateApiDnsRecordsOsp(auth)
		}

		if Username != "" {
			cl.ClusterName = Username + "-" + cl.ClusterName
		} else {
			cl.ClusterName = c.Username + "-" + cl.ClusterName
		}

		err = t.Execute(f, combined{cl, *auth})
		if err != nil {
			return errors.Wrapf(err, "creating config file %s", cl.ClusterName)
		}

		if err := f.Close(); err != nil {
			return err
		}

		log.Debugf("ClustersConfig files for %s generated.", cl.ClusterName)
	} else {
		log.Infof("metadata.json file exists for %s, skipping install config creation.", cl.ClusterName)
	}
	return nil
}

//Generate Psk for submariner tunnels
func GeneratePsk() string {
	var letterRunes = []rune("1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, 64)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

//Parse the main config file
func ParseConfigFile() ([]ClusterData, AuthData, HelmData, OpenshiftData, error) {

	var config ClustersConfig
	var cls []ClusterData

	err := viper.ReadInConfig()
	if err != nil {
		log.Fatalf("Unable to read config")
	}

	err = viper.Unmarshal(&config)
	if err != nil {
		log.Fatalf("Unable to unmarshal config")
	}

	cls = append(cls, config.Clusters...)

	var auth AuthData
	err = viper.UnmarshalKey("authentication", &auth)
	if err != nil {
		log.Fatal(err)
		return nil, AuthData{}, HelmData{}, OpenshiftData{}, err
	}

	var helm HelmData
	err = viper.UnmarshalKey("helm", &helm)
	if err != nil {
		log.Fatal(err)
		return nil, AuthData{}, HelmData{}, OpenshiftData{}, err
	}

	var openshift OpenshiftData
	err = viper.UnmarshalKey("openshift", &openshift)
	if err != nil {
		log.Fatal(err)
		return nil, AuthData{}, HelmData{}, OpenshiftData{}, err
	}

	return cls, auth, helm, openshift, nil
}

//Label private cluster gateway nodes as submariner gateway
func (cl *ClusterData) PreparePrivateGatewayNodes(wg *sync.WaitGroup) error {
	currentDir, _ := os.Getwd()
	kubeConfigFile := filepath.Join(currentDir, ".config", cl.ClusterName, "auth", "kubeconfig")
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfigFile)
	if err != nil {
		return err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}

	nodes, err := clientset.CoreV1().Nodes().List(metav1.ListOptions{
		LabelSelector: "node-role.kubernetes.io/worker=",
	})
	if err != nil {
		return err
	}

	err = cl.LabelGatewayNodes(nodes.Items[0].Name)
	if err != nil {
		return err
	}
	wg.Done()
	return nil
}

func (cl *ClusterData) LabelGatewayNodes(gw string) error {
	infraDetails, err := cl.ExtractInfraDetails()
	if err != nil {
		return err
	}

	currentDir, _ := os.Getwd()
	kubeConfigFile := filepath.Join(currentDir, ".config", cl.ClusterName, "auth", "kubeconfig")
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfigFile)
	if err != nil {
		return err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}

	node, err := clientset.CoreV1().Nodes().Get(gw, metav1.GetOptions{})
	if err != nil {
		return err
	}

	node.Labels["submariner.io/gateway"] = "true"
	_, err = clientset.CoreV1().Nodes().Update(node)
	if err != nil {
		return err
	}
	log.Infof("✔ Node %s was labeled as gateway %s.", node.Name, infraDetails[0])
	return nil
}

//Export submariner broker ca and token
func (cl *ClusterData) ExportBrokerSecretData() (map[string][]byte, error) {
	currentDir, _ := os.Getwd()
	kubeConfigFile := filepath.Join(currentDir, ".config", cl.ClusterName, "auth", "kubeconfig")
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfigFile)
	if err != nil {
		log.Error(err.Error())
		return nil, err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Error(err.Error())
		return nil, err
	}

	saClient := clientset.CoreV1().Secrets("submariner-k8s-broker")

	saList, err := saClient.List(metav1.ListOptions{FieldSelector: "type=kubernetes.io/service-account-token"})
	if err == nil && len(saList.Items) > 0 {
		for _, sa := range saList.Items {
			if strings.Contains(sa.Name, "submariner-k8s-broker-client-token") {
				b := new(bytes.Buffer)
				for key, value := range sa.Annotations {
					_, _ = fmt.Fprintf(b, "%s=\"%s\"\n", key, value)
				}
				if !strings.Contains(b.String(), "openshift.io") {
					log.Debugf("Getting data for %s %s", sa.Name, cl.ClusterName)
					return sa.Data, nil
				}
			}
		}
	} else {
		log.Errorf("Could not get broker token for %s", cl.ClusterName)
	}
	return nil, nil
}

//Extract infra details from metadata.json
func (cl *ClusterData) ExtractInfraDetails() ([]string, error) {
	currentDir, _ := os.Getwd()
	metaJson := filepath.Join(currentDir, ".config", cl.ClusterName, "metadata.json")
	jsonFile, err := os.Open(metaJson)
	if err != nil {
		return nil, err
	}

	byteValue, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	err = json.Unmarshal(byteValue, &result)
	if err != nil {
		return nil, err
	}

	infraDetails := []string{result["infraID"].(string), result["clusterID"].(string), result["clusterName"].(string)}
	return infraDetails, nil
}

// Create OCP4 cluster using IPI
func (cl *ClusterData) CreateOcpCluster(v *OpenshiftData, wg *sync.WaitGroup) error {
	release := strings.Join(strings.Split(strings.Split(v.Version, "-")[0], ".")[:2], ".")

	currentDir, err := os.Getwd()
	if err != nil {
		return err
	}

	configDir := filepath.Join(currentDir, ".config", cl.ClusterName)
	log.Infof("Creating cluster %s platform: %s. Release: %s. Detailed log: %s", cl.ClusterName, cl.Platform.Name, release, configDir+"/.openshift_install.log")
	cmdName := "./bin/openshift-install"
	cmdArgs := []string{"create", "cluster", "--dir", configDir, "--log-level", "debug"}

	cmd := exec.Command(cmdName, cmdArgs...)
	buf := &bytes.Buffer{}
	cmd.Stdout = buf
	cmd.Stderr = buf

	err = cmd.Start()
	if err != nil {
		return errors.Wrapf(err, "Error starting installation: %s. Detailed log: %s", cl.ClusterName, configDir+"/.openshift_install.log")
	}

	err = cmd.Wait()
	if err != nil && strings.Contains(buf.String(), "already exists") {
		log.Debugf("✔ %s %s", err.Error(), cl.ClusterName)
	} else if err != nil {
		return errors.Wrapf(err, "Error waiting for installation completion: %s platform: %s. Detailed log: %s", cl.ClusterName, cl.Platform.Name, configDir+"/.openshift_install.log")
	}

	log.WithFields(log.Fields{
		"cluster": cl.ClusterName,
	}).Debugf("%s %s", cl.ClusterName, buf.String())

	infraDetails, err := cl.ExtractInfraDetails()
	if err != nil {
		return err
	}

	log.Infof("✔ Openshift was installed on %s platform: %s, clusterID: %s.", cl.ClusterName, cl.Platform.Name, infraDetails[0])
	wg.Done()
	return nil
}

//Run api dns creation terraform osp module
func (cl *ClusterData) CreateApiDnsRecordsOsp(a *AuthData) string {
	c, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}

	var infraId string
	if Username != "" {
		infraId = Username + "-" + cl.ClusterName
	} else {
		infraId = c.Username + "-" + cl.ClusterName
	}

	log.Infof("Creating api DNS records for %s platform: %s.", cl.ClusterName, cl.Platform.Name)
	cmdName := "./bin/terraform"
	cmdArgs := []string{
		"apply", "-target", "module." + cl.ClusterName + "-osp-dns",
		"-var", "infra_id=" + infraId,
		"-var", "dns_domain=" + cl.DNSDomain,
		"-var", "public_network_name=" + cl.Platform.ExternalNetwork,
		"-var", "osp_auth_url=" + a.OpenStack.AuthURL,
		"-var", "osp_user_name=" + a.OpenStack.Username,
		"-var", "osp_user_password=" + a.OpenStack.Password,
		"-var", "osp_user_domain_name=" + a.OpenStack.UserDomainName,
		"-var", "osp_tenant_id=" + a.OpenStack.ProjectID,
		"-var", "osp_tenant_name=" + a.OpenStack.ProjectName,
		"-var", "osp_region=" + cl.Platform.Region,
		"-state", "tf/state/" + "terraform-" + cl.ClusterName + "-osp-dns.tfstate",
		"-auto-approve",
	}

	cmd := exec.Command(cmdName, cmdArgs...)
	buf := &bytes.Buffer{}
	cmd.Stdout = buf
	cmd.Stderr = buf

	err = cmd.Start()
	if err != nil {
		log.Errorf("Error starting terraform: %s %s\n %s", cl.ClusterName, err, buf.String())
	}

	err = cmd.Wait()
	if err != nil {
		log.Errorf("Error waiting for dns records creation: %s %s\n %s", cl.ClusterName, err, buf.String())
	}

	log.WithFields(log.Fields{
		"cluster": cl.ClusterName,
	}).Debugf("%s %s", cl.ClusterName, buf.String())

	output := strings.Split(buf.String(), "\n")
	log.Infof("✔ DNS records were created for %s: %s", cl.ClusterName, output[len(output)-2])

	const ansi = "[\u001B\u009B][[\\]()#;?]*(?:(?:(?:[a-zA-Z\\d]*(?:;[a-zA-Z\\d]*)*)?\u0007)|(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PRZcf-ntqry=><~]))"
	var re = regexp.MustCompile(ansi)
	return re.ReplaceAllString(strings.Split(output[len(output)-2], " = ")[1], "")
}

//Run apps dns creation terraform osp module
func (cl *ClusterData) CreateAppsDnsRecordsOsp(a *AuthData, wg *sync.WaitGroup) error {
	infraDetails, err := cl.ExtractInfraDetails()
	if err != nil {
		return err
	}

	log.Infof("Creating vxlan security group rules and apps DNS records for %s platform: %s.", cl.ClusterName, cl.Platform.Name)
	cmdName := "./bin/terraform"
	cmdArgs := []string{
		"apply", "-target", "module." + cl.ClusterName + "-osp-sg",
		"-var", "infra_id=" + infraDetails[0],
		"-var", "dns_domain=" + cl.DNSDomain,
		"-var", "osp_auth_url=" + a.OpenStack.AuthURL,
		"-var", "osp_user_name=" + a.OpenStack.Username,
		"-var", "osp_user_password=" + a.OpenStack.Password,
		"-var", "osp_user_domain_name=" + a.OpenStack.UserDomainName,
		"-var", "osp_tenant_id=" + a.OpenStack.ProjectID,
		"-var", "osp_tenant_name=" + a.OpenStack.ProjectName,
		"-var", "osp_region=" + cl.Platform.Region,
		"-var", "public_network_name=" + cl.Platform.ExternalNetwork,
		"-state", "tf/state/" + "terraform-" + cl.ClusterName + "-osp-sg.tfstate",
		"-auto-approve",
	}

	cmd := exec.Command(cmdName, cmdArgs...)
	buf := &bytes.Buffer{}
	cmd.Stdout = buf
	cmd.Stderr = buf

	err = cmd.Start()
	if err != nil {
		return errors.Wrapf(err, "Error starting terraform: %s\n %s", infraDetails[0], buf.String())
	}

	err = cmd.Wait()
	if err != nil {
		return errors.Wrapf(err, "Error waiting for security group rules creation: %s\n %s", infraDetails[0], err, buf.String())
	}

	log.WithFields(log.Fields{
		"cluster": infraDetails[0],
	}).Debugf("%s %s", infraDetails[0], buf.String())

	output := strings.Split(buf.String(), "\n")
	log.Infof("✔ Security group rules and DNS records were created for %s: %s", infraDetails[0], output[len(output)-2])
	wg.Done()
	return nil
}

func (cl *ClusterData) CreatePublicIpiResourcesAws(wg *sync.WaitGroup) error {

	infraDetails, err := cl.ExtractInfraDetails()
	if err != nil {
		return err
	}

	log.Infof("Applying AWS IPI modifications for %s, platform: %s.", infraDetails[0], cl.Platform.Name)
	cmdName := "./bin/terraform"
	cmdArgs := []string{
		"apply", "-target", "module." + cl.ClusterName + "-aws-ipi",
		"-var", "infra_id=" + infraDetails[0],
		"-var", "aws_region=" + cl.Platform.Region,
		"-state", "tf/state/" + "terraform-" + cl.ClusterName + "-aws-ipi.tfstate",
		"-auto-approve",
	}

	cmd := exec.Command(cmdName, cmdArgs...)
	buf := &bytes.Buffer{}
	cmd.Stdout = buf
	cmd.Stderr = buf

	err = cmd.Start()
	if err != nil {
		return errors.Wrapf(err, "Error starting terraform: %s %s\n %s", cl.ClusterName, err, buf.String())
	}

	err = cmd.Wait()
	if err != nil {
		return errors.Wrapf(err, "Error applying AWS IPI modifications: %s %s\n %s", cl.ClusterName, err, buf.String())
	}

	log.WithFields(log.Fields{
		"cluster": infraDetails[0],
	}).Debugf("%s %s", infraDetails[0], buf.String())

	output := strings.Split(buf.String(), "\n")
	log.Infof("✔ AWS IPI modifications were applied for %s: %s", infraDetails[0], output[len(output)-2])
	wg.Done()
	return nil
}

func (cl *ClusterData) CreateTillerDeployment(wg *sync.WaitGroup) error {
	currentDir, _ := os.Getwd()
	kubeConfigFile := filepath.Join(currentDir, ".config", cl.ClusterName, "auth", "kubeconfig")

	saFile := filepath.Join(currentDir, "deploy/tiller/serviceaccount.json")
	roleFile := filepath.Join(currentDir, "deploy/tiller/clusterrolebinding.json")
	deployFile := filepath.Join(currentDir, "deploy/tiller/tillerdeploy.json")
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfigFile)
	if err != nil {
		return err
	}

	infraDetails, err := cl.ExtractInfraDetails()
	if err != nil {
		return err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return errors.Wrapf(err, "%s", infraDetails[0])
	}

	file, err := os.Open(saFile)
	if err != nil {
		return errors.Wrapf(err, "%s", infraDetails[0])
	}
	dec := json.NewDecoder(file)

	var sa corev1.ServiceAccount
	err = dec.Decode(&sa)
	if err != nil {
		return errors.Wrapf(err, "%s", infraDetails[0])
	}

	saResult, err := clientset.CoreV1().ServiceAccounts("kube-system").Create(&sa)
	if err != nil && strings.Contains(err.Error(), "already exists") {
		log.Debugf("✔ %s %s", err.Error(), infraDetails[0])
	} else if err != nil {
		return errors.Wrapf(err, "%s", infraDetails[0])
	} else {
		log.Debugf("✔ Tiller service account created for %s at: %s", infraDetails[0], saResult.CreationTimestamp)
	}

	file, err = os.Open(roleFile)
	if err != nil {
		return errors.Wrapf(err, "%s", infraDetails[0])
	}
	dec = json.NewDecoder(file)

	var crb rbacv1.ClusterRoleBinding
	err = dec.Decode(&crb)
	if err != nil {
		log.Fatal(err)
	}

	crbResult, err := clientset.RbacV1().ClusterRoleBindings().Create(&crb)
	if err != nil && strings.Contains(err.Error(), "already exists") {
		log.Debugf("✔ %s %s", err.Error(), infraDetails[0])
	} else if err != nil {
		return errors.Wrapf(err, "%s", infraDetails[0])
	} else {
		log.Debugf("✔ Tiller cluster role binding created for %s at: %s", infraDetails[0], crbResult.CreationTimestamp)
	}

	file, err = os.Open(deployFile)
	if err != nil {
		return errors.Wrapf(err, "%s", infraDetails[0])
	}
	dec = json.NewDecoder(file)

	var dep extensionsv1beta1.Deployment
	err = dec.Decode(&dep)
	if err != nil {
		return errors.Wrapf(err, "%s", infraDetails[0])
	}

	deploymentsClient := clientset.ExtensionsV1beta1().Deployments("kube-system")

	_, err = deploymentsClient.Create(&dep)
	if err != nil && strings.Contains(err.Error(), "already exists") {
		log.Infof("✔ %s for %s.", err.Error(), infraDetails[0])
	} else if err != nil {
		return errors.Wrapf(err, "%s", infraDetails[0])
	} else {
		ctx := context.Background()
		tillerTimeout := 5 * time.Minute
		log.Infof("Waiting up to %v for tiller to be created %s...", tillerTimeout, infraDetails[0])
		tillerContext, cancel := context.WithTimeout(ctx, tillerTimeout)
		wait.Until(func() {
			tillerDeployment, err := clientset.ExtensionsV1beta1().Deployments("kube-system").Get("tiller-deploy", metav1.GetOptions{})
			if err == nil && tillerDeployment.Status.ReadyReplicas > 0 {
				if tillerDeployment.Status.ReadyReplicas == 1 {
					log.Infof("✔ Tiller successfully deployed to %s, ready replicas: %v", infraDetails[0], tillerDeployment.Status.ReadyReplicas)
					cancel()
				} else {
					log.Infof("Still waiting for tiller deployment %s, ready replicas: %v", infraDetails[0], tillerDeployment.Status.ReadyReplicas)
				}
			}
		}, 30*time.Second, tillerContext.Done())
		err = tillerContext.Err()
		if err != nil && err != context.Canceled {
			return errors.Wrapf(err, "Error waiting for tiller deployment %s", infraDetails[0])
		}
	}
	wg.Done()
	return nil
}

var clusterCmd = &cobra.Command{
	Use:   "clusters",
	Short: "Create multiple OCP4 clusters",
	Run: func(cmd *cobra.Command, args []string) {

		if Debug {
			log.SetReportCaller(true)
			log.SetLevel(log.DebugLevel)
		}

		clusters, authConfig, _, openshiftConfig, err := ParseConfigFile()
		if err != nil {
			log.Fatal(err)
		}

		var awscls []ClusterData
		var openstackcls []ClusterData
		var publiccls []ClusterData
		var privatecls []ClusterData

		for _, cl := range clusters {
			switch cl.Platform.Name {
			case "aws":
				awscls = append(awscls, cl)
			case "openstack":
				openstackcls = append(openstackcls, cl)
			}
		}

		for _, cl := range clusters {
			switch cl.ClusterType {
			case "public":
				if cl.Platform.Name == "aws" {
					publiccls = append(publiccls, cl)
				}
			case "private":
				privatecls = append(privatecls, cl)
			}
		}

		err = GetDependencies(&openshiftConfig)
		if err != nil {
			log.Fatal(err)
		}

		log.Infof("Generating install configs...")
		for _, cl := range clusters {
			err = GenerateConfigs(cl, &authConfig)
			if err != nil {
				log.Fatal(err)
			}
		}

		var wg sync.WaitGroup
		wg.Add(len(clusters))
		for _, cl := range clusters {
			go func(cl ClusterData) {
				err := cl.CreateOcpCluster(&openshiftConfig, &wg)
				if err != nil {
					defer wg.Done()
					log.Fatal(err)
				}
			}(cl)
		}
		wg.Wait()

		err = TerraformInit()
		if err != nil {
			log.Fatal(err)
		}

		wg.Add(len(publiccls))
		for _, cl := range publiccls {
			go func(cl ClusterData) {
				err := cl.CreatePublicIpiResourcesAws(&wg)
				if err != nil {
					defer wg.Done()
					log.Error(err)
				}
			}(cl)
		}
		wg.Wait()

		wg.Add(len(privatecls))
		for _, cl := range privatecls {
			go func(cl ClusterData) {
				err := cl.PreparePrivateGatewayNodes(&wg)
				if err != nil {
					defer wg.Done()
					log.Error(err)
				}
			}(cl)
		}
		wg.Wait()

		wg.Add(len(clusters))
		for _, cl := range clusters {
			go func(cl ClusterData) {
				err := cl.CreateTillerDeployment(&wg)
				if err != nil {
					defer wg.Done()
					log.Error(err)
				}
			}(cl)
		}
		wg.Wait()
	},
}

func init() {
	var createCmd = &cobra.Command{
		Use:   "create",
		Short: "Create resources",
		PersistentPostRun: func(cmd *cobra.Command, args []string) {
			clusters, _, _, _, err := ParseConfigFile()
			if err != nil {
				log.Fatal(err)
			}
			ModifyKubeConfigFiles(clusters)
		},
	}
	clusterCmd.Flags().StringVarP(&Username, "user", "u", "", "username to override the current username executing the tool")
	rootCmd.AddCommand(createCmd)
	createCmd.AddCommand(clusterCmd)
}
