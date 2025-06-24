package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"encoding/json"
	"fmt"
	"os"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/client-go/rest"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	"github.com/ykachube/cert-manager-webhook-servercore/internal"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	cmd.RunWebhookServer(GroupName,
		&servercoreDNSProviderSolver{},
	)
}

type servercoreDNSProviderSolver struct {
	client *kubernetes.Clientset
}

type servercoreDNSProviderConfig struct {
	SecretRef string `json:"secretName"`
	ZoneName  string `json:"zoneName"`
	ApiUrl    string `json:"apiUrl"`
	AuthURL   string `json:"authUrl"` // Added AuthURL field
}

func getAuthToken(config *internal.Config) (string, error) {
	// Return cached token if still valid
	if config.AuthToken != "" && time.Now().Before(config.TokenExpiry) {
		return config.AuthToken, nil
	}

	// Create auth request
	authRequest := map[string]interface{}{
		"auth": map[string]interface{}{
			"identity": map[string]interface{}{
				"methods": []string{"password"},
				"password": map[string]interface{}{
					"user": map[string]interface{}{
						"name":     config.Username,
						"domain":   map[string]interface{}{"name": config.AccountID},
						"password": config.Password,
					},
				},
			},
			"scope": map[string]interface{}{
				"project": map[string]interface{}{
					"name":   config.ProjectName,
					"domain": map[string]interface{}{"name": config.AccountID},
				},
			},
		},
	}

	jsonData, err := json.Marshal(authRequest)
	if err != nil {
		klog.Errorf("[DEBUG] Marshal failed: %v", err)
		return "", err
	}

	// Make request to auth API
	req, err := http.NewRequest("POST", config.AuthURL+"/auth/tokens", bytes.NewBuffer(jsonData))
	if err != nil {
		klog.Errorf("[DEBUG] NewRequest failed: %v", err)
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Get token from header
	token := resp.Header.Get("X-Subject-Token")
	klog.Infof("token got: %v", token)

	if token == "" {
		klog.Errorf("[DEBUG] no token in response! ")
		return "", errors.New("no token in response")
	}

	// Cache token for 23 hours (tokens last 24 hours)
	config.AuthToken = token
	config.TokenExpiry = time.Now().Add(23 * time.Hour)

	return token, nil
}

func (c *servercoreDNSProviderSolver) Name() string {
	return "servercore"
}

func (c *servercoreDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	klog.V(6).Infof("call function Present: namespace=%s, zone=%s, fqdn=%s",
		ch.ResourceNamespace, ch.ResolvedZone, ch.ResolvedFQDN)

	config, err := clientConfig(c, ch)

	if err != nil {
		return fmt.Errorf("unable to get secret `%s`; %v", ch.ResourceNamespace, err)
	}

	addTxtRecord(config, ch)

	klog.Infof("Presented txt record %v", ch.ResolvedFQDN)

	return nil
}

func (c *servercoreDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	config, err := clientConfig(c, ch)
	if err != nil {
		return fmt.Errorf("unable to get secret `%s`; %v", ch.ResourceNamespace, err)
	}

	zoneId, err := searchZoneId(config)
	if err != nil {
		return fmt.Errorf("unable to find id for zone name `%s`; %v", config.ZoneName, err)
	}

	// List records
	url := fmt.Sprintf("%s/zones/%s/rrset", config.ApiUrl, zoneId)
	klog.Infof("[DEBUG] Listing records with URL: %s", url)

	dnsRecords, err := callDnsApi(url, "GET", nil, config)
	if err != nil {
		klog.Errorf("[DEBUG] Failed to list records: %v", err)
		return nil // Continue with cleanup
	}

	klog.Infof("[DEBUG] Records response: %s", string(dnsRecords))

	// Find the challenge record
	acmePrefix := "_acme-challenge."
	targetName := acmePrefix + recordName(ch.ResolvedFQDN, config.ZoneName)
	klog.Infof("[DEBUG] Looking for record with name: %s", targetName)

	var recordsResp struct {
		Result []struct {
			Id   string `json:"id"`
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"result"`
	}

	if err := json.Unmarshal(dnsRecords, &recordsResp); err != nil {
		klog.Errorf("[DEBUG] Failed to parse records: %v", err)
		return nil
	}

	// Find the TXT record
	var rrsetId string
	for _, record := range recordsResp.Result {
		klog.Infof("[DEBUG] Checking record: %s (type: %s)", record.Name, record.Type)
		if record.Type == "TXT" && strings.Contains(record.Name, targetName) {
			rrsetId = record.Id
			klog.Infof("[DEBUG] Found record to delete: %s", rrsetId)
			break
		}
	}

	if rrsetId == "" {
		klog.Infof("[DEBUG] No record found to delete, may have been removed already")
		return nil
	}

	// Delete TXT record - using exact documented endpoint
	deleteUrl := fmt.Sprintf("%s/zones/%s/rrset/%s", config.ApiUrl, zoneId, rrsetId)
	klog.Infof("[DEBUG] Deleting record with URL: %s", deleteUrl)

	del, err := callDnsApi(deleteUrl, "DELETE", nil, config)
	if err != nil {
		klog.Errorf("[DEBUG] Failed to delete record: %v", err)
		return nil // Don't fail the cleanup
	}

	klog.Infof("[DEBUG] Delete TXT record successful")
	return nil
}

func (c *servercoreDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	k8sClient, err := kubernetes.NewForConfig(kubeClientConfig)
	klog.V(6).Infof("Input variable stopCh is %d length", len(stopCh))
	if err != nil {
		return err
	}

	c.client = k8sClient

	return nil
}

func loadConfig(cfgJSON *extapi.JSON) (servercoreDNSProviderConfig, error) {
	cfg := servercoreDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}

func stringFromSecretData(secretData map[string][]byte, key string) (string, error) {
	data, ok := secretData[key]
	if !ok {
		return "", fmt.Errorf("key %q not found in secret data", key)
	}
	return string(data), nil
}

func addTxtRecord(config internal.Config, ch *v1alpha1.ChallengeRequest) error {
	zoneId, err := searchZoneId(config)
	if err != nil {
		klog.Infof("unable to find id for zone name `%s`; %v", config.ZoneName, err)

		return fmt.Errorf("unable to find id for zone name `%s`; %v", config.ZoneName, err)
	}

	url := fmt.Sprintf("%s/zones/%s/rrset", config.ApiUrl, zoneId)
	klog.Infof("url TXT record call: %s", string(url))

	// Updated to match the working script format
	recordData := map[string]interface{}{
		"name": ch.ResolvedFQDN,
		"type": "TXT",
		"ttl":  60,
		"records": []map[string]string{
			{
				"content": fmt.Sprintf("\"%s\"", ch.Key),
			},
		},
	}

	jsonData, err := json.Marshal(recordData)
	if err != nil {
		klog.Infof("failed to marshal record data: %v", err)
		return fmt.Errorf("failed to marshal record data: %v", err)
	}

	// Log the actual payload for debugging
	klog.Infof("Sending payload: %s", string(jsonData))

	add, err := callDnsApi(url, "POST", bytes.NewBuffer(jsonData), config)
	if err != nil {
		klog.Infof("callDnsApi: %v", err)
		return err
	}

	klog.Infof("Added TXT record result: %s", string(add))

	// Save record ID for cleanup
	var response struct {
		Id string `json:"id"`
	}
	if err := json.Unmarshal(add, &response); err != nil {
		klog.Warningf("Failed to parse record ID from response: %v", err)
	} else {
		// Save record ID somewhere for cleanup
		// For example, you could use annotations on the Challenge resource
	}

	return nil
}

func clientConfig(c *servercoreDNSProviderSolver, ch *v1alpha1.ChallengeRequest) (internal.Config, error) {
	var config internal.Config

	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return config, err
	}
	config.ZoneName = cfg.ZoneName
	config.ApiUrl = cfg.ApiUrl

	// Set default auth URL if not provided in config
	if cfg.AuthURL != "" {
		config.AuthURL = cfg.AuthURL
	} else {
		config.AuthURL = "https://cloud.api.servercore.com/identity/v3"
	}

	secretName := cfg.SecretRef
	sec, err := c.client.CoreV1().Secrets(ch.ResourceNamespace).Get(context.TODO(), secretName, metav1.GetOptions{})
	if err != nil {
		return config, fmt.Errorf("unable to get secret `%s/%s`; %v", secretName, ch.ResourceNamespace, err)
	}

	// Load ServerCore credentials from the secret
	username, err := stringFromSecretData(sec.Data, "username")
	if err != nil {
		return config, fmt.Errorf("unable to get username from secret `%s/%s`; %v", secretName, ch.ResourceNamespace, err)
	}
	config.Username = username

	password, err := stringFromSecretData(sec.Data, "password")
	if err != nil {
		return config, fmt.Errorf("unable to get password from secret `%s/%s`; %v", secretName, ch.ResourceNamespace, err)
	}
	config.Password = password

	accountID, err := stringFromSecretData(sec.Data, "account-id")
	if err != nil {
		return config, fmt.Errorf("unable to get account-id from secret `%s/%s`; %v", secretName, ch.ResourceNamespace, err)
	}
	config.AccountID = accountID

	projectName, err := stringFromSecretData(sec.Data, "project-name")
	if err != nil {
		return config, fmt.Errorf("unable to get project-name from secret `%s/%s`; %v", secretName, ch.ResourceNamespace, err)
	}
	config.ProjectName = projectName

	// Optional auth URL override from secret
	authURL, err := stringFromSecretData(sec.Data, "auth-url")
	if err == nil && authURL != "" {
		config.AuthURL = authURL
	}

	// Get ZoneName by api search if not provided by config
	if config.ZoneName == "" {
		foundZone, err := searchZoneName(config, ch.ResolvedZone)
		if err != nil {
			return config, err
		}
		config.ZoneName = foundZone
	}

	return config, nil
}

/*
Domain name in Servercore is divided in 2 parts: record + zone name. API works
with record name that is FQDN without zone name. Subdomains is a part of
record name and is separated by "."
*/
func recordName(fqdn, domain string) string {
	r := regexp.MustCompile("(.+)\\." + domain + "\\.")
	name := r.FindStringSubmatch(fqdn)
	if len(name) != 2 {
		klog.Errorf("splitting domain name %s failed!", fqdn)
		return ""
	}
	return name[1]
}

func callDnsApi(url, method string, body io.Reader, config internal.Config) ([]byte, error) {
	// Get auth token
	token, err := getAuthToken(&config)
	if err != nil {
		klog.Errorf("[DEBUG] failed to get auth token: %v", err)
		return nil, fmt.Errorf("failed to get auth token: %v", err)
	}

	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return []byte{}, fmt.Errorf("unable to execute request %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Auth-Token", token) // Use X-Auth-Token instead of Auth-API-Token

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		klog.Errorf("[DEBUG] HTTP request failed: %v", err)
		return nil, err
	}

	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	klog.Infof("resp.StatusCode %v", resp.StatusCode)
	klog.Infof("respBody %v", respBody)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 { // Accept any 2xx status code
		return respBody, nil
	}

	text := fmt.Sprintf("Error calling API status: %s url: %s method: %s response: %s",
		resp.Status, url, method, string(respBody))
	klog.Error(text)
	klog.Errorf(text)

	return nil, errors.New(text)
}

func searchZoneId(config internal.Config) (string, error) {
	url := config.ApiUrl + "/zones"

	klog.Infof("[DEBUG] Searching for zones with URL: %s", url)

	zoneRecords, err := callDnsApi(url, "GET", nil, config)
	if err != nil {
		klog.Errorf("[DEBUG] Failed to get zone info: %v", err)
		return "", fmt.Errorf("unable to get zone info %v", err)
	}

	klog.Infof("[DEBUG] Got zone response: %s", string(zoneRecords))

	// Unmarshall response with new structure
	zones := internal.ZoneResponse{}
	readErr := json.Unmarshal(zoneRecords, &zones)
	if readErr != nil {
		klog.Errorf("[DEBUG] Failed to unmarshal zone response: %v", readErr)
		return "", fmt.Errorf("unable to unmarshal response %v", readErr)
	}

	// Find the matching zone by name
	for _, zone := range zones.Result {
		klog.Infof("[DEBUG] Checking zone: %s", zone.Name)
		if zone.Name == config.ZoneName {
			klog.Infof("[DEBUG] Found matching zone! ID: %s", zone.Id)
			return zone.Id, nil
		}
	}

	klog.Errorf("[DEBUG] No zone found with name: %s", config.ZoneName)
	return "", fmt.Errorf("no zone found with name: %s", config.ZoneName)
}

func searchZoneName(config internal.Config, searchZone string) (string, error) {
	parts := strings.Split(searchZone, ".")
	parts = parts[:len(parts)-1]
	for i := 0; i <= len(parts)-2; i++ {
		config.ZoneName = strings.Join(parts[i:], ".")
		zoneId, _ := searchZoneId(config)
		if zoneId != "" {
			klog.Infof("Found ID with ZoneName: %s", config.ZoneName)
			return config.ZoneName, nil
		}
	}
	klog.Errorf("[DEBUG] unable to find servercore dns zone ")
	return "", fmt.Errorf("unable to find servercore dns zone with: %s", searchZone)
}
