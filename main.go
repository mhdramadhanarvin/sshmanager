package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/oauth2/google"
	"golang.org/x/term"

	"context"

	"golang.org/x/oauth2"
	"google.golang.org/api/drive/v3"
	"google.golang.org/api/option"
)

const (
	cipherKeyLen = 32
	saltLen      = 16
	iterCount    = 10000
)

type Profile struct {
	Name              string `json:"name"`
	Host              string `json:"host"`
	Port              int    `json:"port"`
	Username          string `json:"username"`
	Password          string `json:"password,omitempty"`
	PrivateKeyContent string `json:"private_key_content,omitempty"`
}

type SecureStorage struct {
	Salt     []byte    `json:"salt"`
	Data     []byte    `json:"data"`
	Profiles []Profile `json:"-"`
}

type AppSettings struct {
	AutoSync bool `json:"auto_sync"`
}

var appDir = os.Getenv("HOME") + "/.sshmanager"

func (s *SecureStorage) Encrypt(password string) error {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("failed to generate salt: %v", err)
	}
	s.Salt = salt

	key := pbkdf2.Key([]byte(password), salt, iterCount, cipherKeyLen, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %v", err)
	}

	data, err := json.Marshal(s.Profiles)
	if err != nil {
		return fmt.Errorf("failed to marshal data: %v", err)
	}

	s.Data = gcm.Seal(nonce, nonce, data, nil)
	s.Profiles = nil
	return nil
}

func (s *SecureStorage) Decrypt(password string) error {
	if len(s.Salt) != saltLen {
		return fmt.Errorf("invalid salt length")
	}

	key := pbkdf2.Key([]byte(password), s.Salt, iterCount, cipherKeyLen, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %v", err)
	}

	if len(s.Data) < gcm.NonceSize() {
		return fmt.Errorf("invalid data length")
	}

	nonce, ciphertext := s.Data[:gcm.NonceSize()], s.Data[gcm.NonceSize():]
	data, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("decryption failed: %v", err)
	}

	return json.Unmarshal(data, &s.Profiles)
}

func promptPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	return string(bytePassword), err
}

func loadProfiles(dir string) (*SecureStorage, error) {
	settings, err := loadSettings()
	if err != nil {
		log.Fatal(err)
	}

	path := filepath.Join(dir, "profiles.enc")
	if _, err := os.Stat(path); os.IsNotExist(err) && settings.AutoSync {

		// Try to download from Drive.
		driveSrv, err := getDriveClient()
		if err != nil {
			log.Printf("Failed to initialize Drive client: %v", err)
		} else if downloadErr := downloadFromDrive(driveSrv); downloadErr != nil {
			log.Printf("Failed to download from Drive: %v", downloadErr)
		}
	}

	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &SecureStorage{}, nil
		}
		return nil, err
	}
	defer file.Close()

	var s SecureStorage
	if err := json.NewDecoder(file).Decode(&s); err != nil {
		return nil, err
	}

	password, err := promptPassword("Enter master password : ")
	if err != nil {
		return nil, err
	}
	if err := s.Decrypt(password); err != nil {
		log.Fatal("❌ Wrong master password")
	}

	return &s, nil
}

func saveProfiles(dir string, s *SecureStorage) error {
	password, err := promptPassword("Enter master password : ")
	if err != nil {
		return err
	}
	if err := s.Encrypt(password); err != nil {
		return err
	}

	path := filepath.Join(dir, "profiles.enc")
	dirPath := filepath.Dir(path)
	if err := os.MkdirAll(dirPath, 0700); err != nil {
		return err
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	settings, err := loadSettings()
	if err != nil {
		log.Printf("Failed to load settings: %v", err)
	} else if settings.AutoSync {
		driveSrv, err := getDriveClient()
		if err != nil {
			log.Printf("Failed to initialize Drive client: %v", err)
		} else if uploadErr := uploadToDrive(driveSrv); uploadErr != nil {
			log.Printf("Failed to upload to Drive: %v", uploadErr)
		}
	}

	return json.NewEncoder(file).Encode(s)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("🚀 Usage: sshmanager <command>")
		fmt.Println()
		fmt.Println("Commands:")
		fmt.Println("  add       Add a new SSH entry.")
		fmt.Println("  list      List all entries")
		fmt.Println("  delete    Remove an entry")
		fmt.Println("  connect   Connect into saved SSH ")
		fmt.Println("  sync      Sync data to Google Drive")
		fmt.Println("  setting   Settings to sync Google Drive")
		fmt.Println("  auth      Auth into Google Account")
		os.Exit(1)
	}

	settings, err := loadSettings()
	if err != nil {
		log.Fatal(err)
	}

	dir := os.Getenv("HOME") + "/.sshmanager"
	command := os.Args[1]

	switch command {
	case "add":
		addProfile(dir)
	case "list":
		listProfiles(dir, false)
	case "delete":
		if len(os.Args) < 3 {
			fmt.Println("Usage: sshmanager delete <name>")
			os.Exit(1)
		}
		deleteProfile(dir, os.Args[2])
	case "connect":
		if len(os.Args) < 3 {
			fmt.Println("Usage: sshmanager connect <name>")
			os.Exit(1)
		}
		connectProfile(dir, os.Args[2])
	case "setting":
		saveSetting()
	case "auth":
		authGoogle()
	case "sync":
		syncDrive(settings.AutoSync)
	default:
		fmt.Println("Unknown command")
		os.Exit(1)
	}
}

func addProfile(dir string) {
	s, err := loadProfiles(dir)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Adding a new SSH profile:")
	scanner := bufio.NewScanner(os.Stdin)

	fmt.Print("Name: ")
	scanner.Scan()
	name := scanner.Text()

	fmt.Print("Host: ")
	scanner.Scan()
	host := scanner.Text()

	fmt.Print("Port (default 22): ")
	scanner.Scan()
	portStr := scanner.Text()
	port := 22
	fmt.Sscanf(portStr, "%d", &port)

	fmt.Print("Username: ")
	scanner.Scan()
	username := scanner.Text()

	fmt.Print("Password (leave blank if using key): ")
	passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatal(err)
	}
	password := string(passwordBytes)
	fmt.Println()

	fmt.Print("Private key file path (leave blank if using password): ")
	scanner.Scan()
	keyPath := scanner.Text()

	var keyContent string
	if keyPath != "" {
		keyBytes, err := os.ReadFile(keyPath)
		if err != nil {
			log.Fatalf("Failed to read key file: %v", err)
		}
		stat, err := os.Stat(keyPath)
		if err == nil && stat.Mode().Perm()&0007 != 0 {
			fmt.Printf("Warning: Key file '%s' is readable by others (permissions: %s). Consider securing it with 'chmod 600 %s'.\n", keyPath, stat.Mode(), keyPath)
		}
		keyContent = base64.StdEncoding.EncodeToString(keyBytes)
	}

	s.Profiles = append(s.Profiles, Profile{name, host, port, username, password, keyContent})

	if err := saveProfiles(dir, s); err != nil {
		log.Fatal(err)
	}

	settings, err := loadSettings()
	if err != nil {
		log.Fatal(err)
	}
	syncDrive(settings.AutoSync)

	fmt.Println("Profile added successfully.")
}

func listProfiles(dir string, quiet bool) {
	s, err := loadProfiles(dir)
	if err != nil {
		log.Fatal(err)
	}

	if len(s.Profiles) == 0 {
		fmt.Println("No profiles found.")
		return
	}

	if !quiet {
		fmt.Println("Stored profiles:")
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "\t\t\t")
	fmt.Println("📋 Profiles :")
	fmt.Fprintln(w, "Profile\tHost\tUsername\tAuth Type")
	for _, entry := range s.Profiles {
		authType := "Password"
		if entry.PrivateKeyContent != "" {
			authType = "Private Key"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", entry.Name, entry.Host, entry.Username, authType)
	}
	if err := w.Flush(); err != nil {
		log.Fatal(err)
	}

}

func deleteProfile(dir string, name string) {
	s, err := loadProfiles(dir)
	if err != nil {
		log.Fatal(err)
	}

	for i, p := range s.Profiles {
		if p.Name == name {
			s.Profiles = append(s.Profiles[:i], s.Profiles[i+1:]...)
			if err := saveProfiles(dir, s); err != nil {
				log.Fatal(err)
			}
			fmt.Println("Profile deleted.")
			return
		}
	}
	fmt.Println("Profile not found.")

	settings, err := loadSettings()
	if err != nil {
		log.Fatal(err)
	}
	syncDrive(settings.AutoSync)

}

func connectProfile(dir string, name string) {
	s, err := loadProfiles(dir)
	if err != nil {
		log.Fatal(err)
	}

	var profile *Profile
	for _, p := range s.Profiles {
		if p.Name == name {
			profile = &p
			break
		}
	}
	if profile == nil {
		fmt.Println("Profile not found.")
		os.Exit(1)
	}

	tempFile, err := os.CreateTemp("", "sshmanager_key_*.pem")
	if err != nil {
		log.Fatal("Failed to create temp key file:", err)
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	if profile.PrivateKeyContent != "" {
		// Decode and write key to temp file
		keyBytes, err := base64.StdEncoding.DecodeString(profile.PrivateKeyContent)
		if err != nil {
			log.Fatal("Failed to decode key content:", err)
		}
		_, err = tempFile.Write(keyBytes)
		if err != nil {
			log.Fatal("Failed to write key to temp file:", err)
		}
		tempFile.Close()

		// Set secure permissions
		if err := os.Chmod(tempFile.Name(), 0600); err != nil {
			log.Fatal("Failed to set temp file permissions:", err)
		}

		cmd := exec.Command("ssh", "-i", tempFile.Name(), "-p", fmt.Sprintf("%d", profile.Port),
			"-o", "ServerAliveInterval=60",
			"-o", "ServerAliveCountMax=10",
			"-o", "TCPKeepAlive=yes",
			fmt.Sprintf("%s@%s", profile.Username, profile.Host))
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			log.Fatal(err)
		}
	} else if profile.Password != "" {
		cmd := exec.Command("sshpass", "-p", profile.Password, "ssh", "-p", fmt.Sprintf("%d", profile.Port),
			"-o", "ServerAliveInterval=60",
			"-o", "ServerAliveCountMax=10",
			"-o", "TCPKeepAlive=yes",
			fmt.Sprintf("%s@%s", profile.Username, profile.Host))
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			log.Fatal(err)
		}
	} else {
		fmt.Println("No password or key specified.")
		os.Exit(1)
	}
}
func loadSettings() (*AppSettings, error) {
	settingsPath := filepath.Join(appDir, "settings.json")
	file, err := os.Open(settingsPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Prompt user to set auto-sync (only on first run).
			fmt.Print("Enable auto-sync to Google Drive? (y/n): ")
			scanner := bufio.NewScanner(os.Stdin)
			scanner.Scan()
			resp := scanner.Text()
			autoSync := strings.ToLower(resp) == "y" || resp == "yes"
			settings := &AppSettings{AutoSync: autoSync}
			return settings, saveSettings(settings)
		}
		return nil, err
	}
	defer file.Close()

	var settings AppSettings
	if err := json.NewDecoder(file).Decode(&settings); err != nil {
		return nil, err
	}
	return &settings, nil
}

func saveSettings(settings *AppSettings) error {
	settingsPath := filepath.Join(appDir, "settings.json")
	dirPath := filepath.Dir(settingsPath)
	if err := os.MkdirAll(dirPath, 0700); err != nil {
		return err
	}

	file, err := os.OpenFile(settingsPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	return json.NewEncoder(file).Encode(settings)
}

func getDriveClient() (*drive.Service, error) {
	ctx := context.Background()
	config := &oauth2.Config{
		ClientID:     "<client_id>",
		ClientSecret: "<cllient_secret>",
		Scopes:       []string{drive.DriveFileScope},
		Endpoint:     google.Endpoint,
		RedirectURL:  "urn:ietf:wg:oauth:2.0:oob",
	}

	tokenFile := filepath.Join(appDir, "token.json")
	tok, err := tokenFromFile(tokenFile)
	if err != nil {
		tok = getTokenFromWeb(config)
		saveToken(tokenFile, tok)
	}

	client := config.Client(ctx, tok)
	result, err := drive.NewService(ctx, option.WithHTTPClient(client))
	return result, nil
}

func tokenFromFile(file string) (*oauth2.Token, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	tok := &oauth2.Token{}
	err = json.NewDecoder(f).Decode(tok)
	return tok, err
}

func saveToken(path string, token *oauth2.Token) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Unable to cache oauth token: %v", err)
	}
	defer f.Close()
	json.NewEncoder(f).Encode(token)
}

func getTokenFromWeb(config *oauth2.Config) *oauth2.Token {
	authURL := config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	fmt.Printf("Go to the following link in your browser then type the "+
		"authorization code: \n%v\n", authURL)

	fmt.Println()
	fmt.Print("Enter token : ")

	var authCode string
	if _, err := fmt.Scan(&authCode); err != nil {
		log.Fatalf("Unable to read authorization code %v", err)
	}

	tok, err := config.Exchange(context.TODO(), authCode)
	if err != nil {
		log.Fatalf("Unable to retrieve token from web %v", err)
	}
	return tok
}

func uploadToDrive(driveSrv *drive.Service) error {
	filePath := filepath.Join(appDir, "profiles.enc")
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open profiles file: %v", err)
	}
	defer file.Close()

	// Check if file exists on Drive; update or create.
	query := fmt.Sprintf("name='%s' and trashed=false", "sshmanager_profiles.enc")
	resp, err := driveSrv.Files.List().Q(query).Do()
	if err != nil {
		return err
	}

	var fileID string
	if len(resp.Files) > 0 {
		fileID = resp.Files[0].Id
	}

	driveFile := &drive.File{Name: "sshmanager_profiles.enc"}
	if fileID != "" {
		_, err = driveSrv.Files.Update(fileID, driveFile).Media(file).Do()
	} else {
		_, err = driveSrv.Files.Create(driveFile).Media(file).Do()
	}
	return err
}

func downloadFromDrive(driveSrv *drive.Service) error {
	query := fmt.Sprintf("name='%s' and trashed=false", "sshmanager_profiles.enc")
	resp, err := driveSrv.Files.List().Q(query).Do()
	if err != nil {
		return err
	}
	if len(resp.Files) == 0 {
		return nil
	}

	fileID := resp.Files[0].Id
	respDown, err := driveSrv.Files.Get(fileID).Download()
	if err != nil {
		return err
	}
	defer respDown.Body.Close()

	filePath := filepath.Join(appDir, "profiles.enc")
	outFile, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer outFile.Close()

	_, err = io.Copy(outFile, respDown.Body)
	return err
}
func saveSetting() {
	fmt.Println("Configuring auto-sync to Google Drive:")
	fmt.Print("Enable auto-sync? (y/n): ")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	resp := scanner.Text()
	autoSync := strings.ToLower(resp) == "y" || resp == "yes"
	settings := &AppSettings{AutoSync: autoSync}
	if err := saveSettings(settings); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Setting saved.")
}

func authGoogle() {
	fmt.Println("Authenticating with Google...")
	_, err := getDriveClient()
	if err != nil {
		log.Fatal("Authentication failed:", err)
	}
	fmt.Println("Authentication successful. Token saved.")
}

func syncDrive(autoSync bool) {
	if !autoSync {
		fmt.Println("Auto-sync is disabled. Enable it first via 'save-setting' or edit settings.json.")
		return
	}

	driveSrv, err := getDriveClient()
	if err != nil {
		log.Fatal("Failed to get Drive client:", err)
	}

	// Check local file and sync accordingly.
	localPath := filepath.Join(appDir, "profiles.enc")
	if _, err := os.Stat(localPath); err == nil {
		// Upload local to Drive.
		if err := uploadToDrive(driveSrv); err != nil {
			log.Fatal("Upload failed:", err)
		}
		fmt.Println("Uploaded to Drive.")
	} else {
		// Download from Drive.
		if err := downloadFromDrive(driveSrv); err != nil {
			log.Fatal("Download failed:", err)
		}
		fmt.Println("Downloaded from Drive.")
	}
}
