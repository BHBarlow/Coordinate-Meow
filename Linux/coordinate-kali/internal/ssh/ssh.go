package ssh

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/bramvdbogaerde/go-scp"
	"github.com/melbahja/goph"

	. "github.com/LByrgeCP/coordinate-kali/internal/config"
	. "github.com/LByrgeCP/coordinate-kali/internal/globals"
	"github.com/LByrgeCP/coordinate-kali/internal/logger"
	"github.com/LByrgeCP/coordinate-kali/internal/utils"
)

func SsherWrapper(i Instance, client *goph.Client) {
	logger.Debug(fmt.Sprintf("Starting SsherWrapper for instance: %+v", i))
	var wg sync.WaitGroup

	// Resolve hostname early so downloads can use it for directory names
	if i.Hostname == "" {
		output, err := client.Run("hostname")
		if err != nil {
			output, err = client.Run("cat /etc/hostname")
		}
		if err == nil && !strings.Contains(string(output), "No such file or directory") {
			i.Hostname = strings.TrimSpace(string(output))
		} else {
			i.Hostname = i.IP
		}
		logger.Debug(fmt.Sprintf("Resolved hostname early: %s", i.Hostname))
	}

	// Upload local files/dirs if -F flags were specified
	if len(*UploadFiles) > 0 {
		logger.Debug(fmt.Sprintf("Upload files requested: %v", *UploadFiles))
		UploadToRemote(i, client)
	}

	// Download remote directories if -D flags were specified
	if len(*DownloadDirs) > 0 {
		logger.Debug(fmt.Sprintf("Download directories requested: %v", *DownloadDirs))
		DownloadRemoteDirs(i, client)
	}

	// If only uploading/downloading (no scripts or commands), we're done
	if len(Commands) == 0 && len(Scripts) == 0 {
		TotalRuns++
		return
	}

	// Handle direct commands if specified
	if len(Commands) > 0 {
		logger.Debug("Executing direct commands instead of scripts")
		for _, command := range Commands {
			logger.Debug(fmt.Sprintf("Processing command: %s", command))
			i.Script = fmt.Sprintf("command: %s", command) // For logging purposes

			// Build full command with environment variables
			var fullCommand string
			for _, cmd := range EnvironCmds {
				fullCommand += fmt.Sprintf("%s ", cmd)
			}
			fullCommand += command

			wg.Add(1)
			go ssherCommand(i, client, fullCommand, &wg)
			i.ID++
		}
		wg.Wait()
		logger.Debug("Finished executing all commands in SsherWrapper.")
		return
	}

	// Handle scripts (existing logic)
	first := true
	for _, path := range Scripts {
		logger.Debug(fmt.Sprintf("Processing script path: %s", path))
		var Script string
		i.Script = path

		ScriptContents, err := os.ReadFile(path)
		if err != nil {
			logger.Crit(i, errors.New("Error reading "+i.Script+": "+err.Error()))
			continue
		}
		for _, cmd := range EnvironCmds {
			Script += fmt.Sprintf("%s ", cmd)
		}
		Script += string(ScriptContents)

		for t := 0; t < *Threads && t < len(Scripts); t++ {
			if first {
				logger.Debug("Launching first thread for script execution.")
				first = false
			}
			wg.Add(1)
			go ssher(i, client, Script, &wg)
			i.ID++
		}
	}

	wg.Wait()
	logger.Debug("Finished executing all threads in SsherWrapper.")
}

func ssherCommand(i Instance, client *goph.Client, command string, wg *sync.WaitGroup) {
	defer wg.Done()

	logger.Debug(fmt.Sprintf("Starting ssherCommand for instance: %+v with command: %s", i, command))

	// Test SSH connection validity
	output, err := client.Run("echo a ; asdfhasdf")
	if len(output) == 0 {
		logger.Err(fmt.Sprintf("%s: Couldn't read stdout. Coordinate does not work with this host's shell probably\n", i.IP))
		BrokenHosts = append(BrokenHosts, i.IP)
		return
	}

	elevated := true
	if i.Username != "root" {
		elevated = false
		logger.Debug(fmt.Sprintf("User '%s' is not root.", i.Username))
		if *Sudo {
			logger.Debug("Sudo is enabled. Attempting privilege escalation.")
			if escalateSudo(i, client) {
				elevated = true
				logger.InfoExtra(i, "Privilege escalation succeeded.")
			} else {
				logger.InfoExtra(i, "Privilege escalation failed.")
			}
		} else {
			logger.InfoExtra(i, "Not root, not sudoing. Proceeding with user.")
		}
	}

	// Get hostname for logging
	name := "hostname"
	output, err = client.Run(name)
	if err != nil {
		logger.Debug("Hostname command failed, attempting 'cat /etc/hostname'")
		name = "cat /etc/hostname"
		output, err = client.Run(name)
	}
	stroutput := string(output)
	if !strings.Contains(stroutput, "No such file or directory") {
		i.Hostname = strings.TrimSpace(stroutput)
		logger.Debug(fmt.Sprintf("Resolved hostname: %s", i.Hostname))
	} else {
		i.Hostname = i.IP
		logger.Debug("No hostname found.")
	}

	// Update output file path with placeholders
	i.Outfile = strings.Replace(i.Outfile, "%i%", i.IP, -1)
	i.Outfile = strings.Replace(i.Outfile, "%h%", i.Hostname, -1)
	i.Outfile = strings.Replace(i.Outfile, "%s%", "command", -1) // Use "command" as script name replacement

	logger.Debug(fmt.Sprintf("Resolved output file path: %s", i.Outfile))

	// Execute command with timeout
	ctx, cancel := context.WithTimeout(context.Background(), Timeout)
	defer cancel()

	var execCommand string
	if elevated || !*Sudo {
		execCommand = command
	} else {
		execCommand = fmt.Sprintf("echo \"%s\" | sudo -S bash -c '%s'", i.Password, command)
	}
	logger.Debug(fmt.Sprintf("Executing command: %s", execCommand))

	output, err = client.RunContext(ctx, execCommand)
	stroutput = string(output)

	if err != nil {
		if strings.Contains(err.Error(), "context deadline exceeded") {
			if len(i.Hostname) > 0 {
				AnnoyingErrs = append(AnnoyingErrs, fmt.Sprintf("Command timed out on %s", i.Hostname))
			} else {
				AnnoyingErrs = append(AnnoyingErrs, fmt.Sprintf("Command timed out on %s", i.IP))
			}
		} else {
			logger.Err(fmt.Sprintf("%s: Error running command: %s\n", i.IP, err))
		}
	}

	if len(stroutput) > 0 {
		logger.Stdout(i, stroutput)
		if *CreateConfig != "" {
			for _, line := range strings.Split(stroutput, "\n") {
				parts := strings.Split(line, ",")
				if len(parts) < 2 || parts[0] != "root" {
					continue
				}
				Password := parts[1]
				UpdateEntry(ConfigEntry{IP: i.IP, Username: "root", Password: Password})
			}
		}
	}

	TotalRuns++
	logger.Debug(fmt.Sprintf("Total runs incremented: %d", TotalRuns))
}

func ssher(i Instance, client *goph.Client, script string, wg *sync.WaitGroup) {
	defer wg.Done()

	logger.Debug(fmt.Sprintf("Starting ssher for instance: %+v with script length: %d", i, len(script)))

	filename := fmt.Sprintf("%s/%s", *TmpDir, utils.GenerateRandomFileName(16))
	remoteFilename := fmt.Sprintf("/tmp/%s", utils.GenerateRandomFileName(16))
	logger.Debug(fmt.Sprintf("Generated temporary filename: %s", filename))

	output, err := client.Run("echo a ; asdfhasdf")
	if len(output) == 0 {
		logger.Err(fmt.Sprintf("%s: Couldn't read stdout. Coordinate does not work with this host's shell probably\n", i.IP))
		BrokenHosts = append(BrokenHosts, i.IP)
		return
	}

	elevated := true
	if i.Username != "root" {
		elevated = false
		logger.Debug(fmt.Sprintf("User '%s' is not root.", i.Username))
		if *Sudo {
			logger.Debug("Sudo is enabled. Attempting privilege escalation.")
			if escalateSudo(i, client) {
				elevated = true
				logger.InfoExtra(i, "Privilege escalation succeeded.")
			} else {
				logger.InfoExtra(i, "Privilege escalation failed.")
			}
		} else {
			logger.InfoExtra(i, "Not root, not sudoing. Proceeding with user.")
		}
	}

	name := "hostname"
	output, err = client.Run(name)
	if err != nil {
		logger.Debug("Hostname command failed, attempting 'cat /etc/hostname'")
		name = "cat /etc/hostname"
		output, err = client.Run(name)
	}
	stroutput := string(output)
	if !strings.Contains(stroutput, "No such file or directory") {
		i.Hostname = strings.TrimSpace(stroutput)
		logger.Debug(fmt.Sprintf("Resolved hostname: %s", i.Hostname))
	} else {
		i.Hostname = i.IP
		logger.Debug("No hostname found.")
	}

	i.Outfile = strings.Replace(i.Outfile, "%i%", i.IP, -1)
	i.Outfile = strings.Replace(i.Outfile, "%h%", i.Hostname, -1)
	i.Outfile = strings.Replace(i.Outfile, "%s%", strings.TrimSuffix(i.Script, ".sh"), -1)

	logger.Debug(fmt.Sprintf("Resolved output file path: %s", i.Outfile))

	err = os.WriteFile(filename, []byte(script), 0644)
	if err != nil {
		logger.Err(fmt.Sprintf("Error writing to temporary file: %s", filename))
		return
	}
	logger.Debug(fmt.Sprintf("Script written to temporary file: %s", filename))

	logger.Debug(fmt.Sprintf("Converting to unix endings: %s", filename))
	err = utils.Dos2unix(filename)
	if err != nil {
		logger.Err(fmt.Sprintf("Error converting file to unix endings: %s", err))
	}

	err = Upload(client, filename, remoteFilename)
	if err != nil {
		logger.ErrExtra(i, err)
		os.Remove(filename)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), Timeout)
	defer cancel()

	var command string
	if elevated || !*Sudo {
		command = fmt.Sprintf("%s ; rm %s", remoteFilename, remoteFilename)
	} else {
		command = fmt.Sprintf("echo \"%s\" | sudo -S %s; sudo rm %s", i.Password, remoteFilename, remoteFilename)
	}
	logger.Debug(fmt.Sprintf("Executing command: %s", command))

	output, err = client.RunContext(ctx, command)
	stroutput = string(output)

	if err != nil {
		if strings.Contains(err.Error(), "context deadline exceeded") {
			if len(i.Hostname) > 0 {
				AnnoyingErrs = append(AnnoyingErrs, fmt.Sprintf("%s timed out on %s", i.Script, i.Hostname))
			} else {
				AnnoyingErrs = append(AnnoyingErrs, fmt.Sprintf("%s timed out on %s", i.Script, i.IP))
			}
		} else {
			logger.Err(fmt.Sprintf("%s: Error running script: %s\n", i.IP, err))
		}
	}
	if len(stroutput) > 0 {
		logger.Stdout(i, stroutput)
		if *CreateConfig != "" {
			for _, line := range strings.Split(stroutput, "\n") {
				parts := strings.Split(line, ",")
				if len(parts) < 2 || parts[0] != "root" {
					continue
				}
				Password := parts[1]
				UpdateEntry(ConfigEntry{IP: i.IP, Username: "root", Password: Password})
			}
		}
	}
	os.Remove(filename)
	logger.Debug(fmt.Sprintf("Removed temporary file: %s", filename))

	TotalRuns++
	logger.Debug(fmt.Sprintf("Total runs incremented: %d", TotalRuns))
}

// UploadToRemote uploads local files/directories to remote hosts.
// Uses streaming tar over SSH stdin — no temp files, no SCP binary needed on remote.
// Format: -F "local_path;remote_path"
func UploadToRemote(i Instance, client *goph.Client) {
	var wg sync.WaitGroup
	for _, entry := range *UploadFiles {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		wg.Add(1)
		go func(entry string) {
			defer wg.Done()
			uploadSingleEntry(i, client, entry)
		}(entry)
	}
	wg.Wait()
}

func uploadSingleEntry(i Instance, client *goph.Client, entry string) {
	// Parse local;remote syntax
	parts := strings.SplitN(entry, ";", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		logger.ErrExtra(i, fmt.Sprintf("Invalid upload format '%s' — use 'local_path;remote_path'", entry))
		return
	}
	localPath := strings.TrimSpace(parts[0])
	remotePath := strings.TrimSpace(parts[1])

	// Check local path exists
	info, err := os.Stat(localPath)
	if err != nil {
		logger.ErrExtra(i, fmt.Sprintf("Local path '%s' not found: %s", localPath, err))
		return
	}

	logger.InfoExtra(i, fmt.Sprintf("Uploading %s -> %s (streaming)", localPath, remotePath))

	if info.IsDir() {
		err = streamUploadDir(client, localPath, remotePath)
	} else {
		err = streamUploadFile(client, localPath, remotePath)
	}

	if err != nil {
		logger.ErrExtra(i, fmt.Sprintf("Failed to upload '%s': %s", localPath, err))
	} else {
		logger.InfoExtra(i, fmt.Sprintf("Successfully uploaded %s -> %s", localPath, remotePath))
	}
}

// streamUploadDir tars a local directory and streams it over SSH stdin to extract on remote.
// One pipe, no temp files on either side.
func streamUploadDir(client *goph.Client, localDir string, remotePath string) error {
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	stdin, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to get stdin pipe: %w", err)
	}

	// Remote: create destination and extract tar from stdin
	remoteCmd := fmt.Sprintf("mkdir -p %s && tar xf - -C %s", remotePath, remotePath)
	if err := session.Start(remoteCmd); err != nil {
		return fmt.Errorf("failed to start remote extract: %w", err)
	}

	// Local: tar the directory and write to SSH stdin
	writeErr := utils.WriteTarToWriter(localDir, stdin)
	stdin.Close() // Signal EOF to remote tar

	sessionErr := session.Wait()

	if writeErr != nil {
		return fmt.Errorf("local tar error: %w", writeErr)
	}
	if sessionErr != nil {
		return fmt.Errorf("remote extract error: %w", sessionErr)
	}
	return nil
}

// streamUploadFile streams a single file over SSH stdin using cat.
// Faster than SCP for single files — no protocol overhead.
func streamUploadFile(client *goph.Client, localFile string, remotePath string) error {
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	stdin, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to get stdin pipe: %w", err)
	}

	// Get local file info for permissions
	info, err := os.Stat(localFile)
	if err != nil {
		return fmt.Errorf("failed to stat local file: %w", err)
	}

	// Determine if remotePath is a directory (ends with /) or full path
	remoteFile := remotePath
	if strings.HasSuffix(remotePath, "/") {
		remoteFile = remotePath + filepath.Base(localFile)
	}

	// Remote: create parent dir and cat stdin to file, preserve executable bit
	perm := "644"
	if info.Mode()&0111 != 0 {
		perm = "755"
	}
	remoteCmd := fmt.Sprintf("mkdir -p \"$(dirname '%s')\" && cat > '%s' && chmod %s '%s'",
		remoteFile, remoteFile, perm, remoteFile)
	if err := session.Start(remoteCmd); err != nil {
		return fmt.Errorf("failed to start remote write: %w", err)
	}

	// Stream local file to SSH stdin
	f, err := os.Open(localFile)
	if err != nil {
		stdin.Close()
		return fmt.Errorf("failed to open local file: %w", err)
	}

	_, copyErr := io.Copy(stdin, f)
	f.Close()
	stdin.Close()

	sessionErr := session.Wait()

	if copyErr != nil {
		return fmt.Errorf("stream error: %w", copyErr)
	}
	if sessionErr != nil {
		return fmt.Errorf("remote write error: %w", sessionErr)
	}
	return nil
}

func DownloadRemoteDirs(i Instance, client *goph.Client) {
	hostname := i.IP
	if i.Hostname != "" {
		hostname = i.Hostname
	}
	localBase := filepath.Join("output", "downloads", hostname)
	if err := os.MkdirAll(localBase, 0755); err != nil {
		logger.ErrExtra(i, fmt.Sprintf("Failed to create local download dir: %s", err))
		return
	}

	var wg sync.WaitGroup
	for _, entry := range *DownloadDirs {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		wg.Add(1)
		go func(entry string) {
			defer wg.Done()
			downloadSingleDir(i, client, entry, localBase)
		}(entry)
	}
	wg.Wait()
}

func downloadSingleDir(i Instance, client *goph.Client, entry string, localBase string) {
	// Support remote;local syntax: -D /etc/ssh;/var/backups/ssh
	remotePath := entry
	localDest := ""
	if idx := strings.Index(entry, ";"); idx != -1 {
		remotePath = strings.TrimSpace(entry[:idx])
		localDest = strings.TrimSpace(entry[idx+1:])
	}

	// Determine extraction target
	var extractDir string
	if localDest != "" && filepath.IsAbs(localDest) {
		extractDir = localDest
	} else if localDest != "" {
		extractDir = filepath.Join(localBase, localDest)
	} else {
		extractDir = localBase
	}
	if err := os.MkdirAll(extractDir, 0755); err != nil {
		logger.ErrExtra(i, fmt.Sprintf("Failed to create extract dir '%s': %s", extractDir, err))
		return
	}

	tarPath := strings.TrimPrefix(remotePath, "/")

	// Try streaming tar directly over SSH — no temp files on remote, download
	// starts immediately as tar runs. Falls back to file-based if streaming fails.
	// Order: tar.gz stream → tar stream → file-based fallback

	// 1) Stream tar.gz directly over SSH stdout
	logger.InfoExtra(i, fmt.Sprintf("Downloading %s -> %s (streaming)", remotePath, extractDir))
	streamCmd := fmt.Sprintf("tar czf - -C / %s 2>/dev/null", tarPath)
	if err := streamTarOverSSH(client, streamCmd, extractDir, true); err == nil {
		logger.InfoExtra(i, fmt.Sprintf("Successfully downloaded %s -> %s", remotePath, extractDir))
		return
	} else {
		logger.Debug(fmt.Sprintf("Streaming tar.gz failed for '%s': %s, trying pipe...", remotePath, err))
	}

	// 2) Stream tar piped through gzip (some tars don't support -z)
	streamCmd = fmt.Sprintf("tar cf - -C / %s 2>/dev/null | gzip 2>/dev/null", tarPath)
	if err := streamTarOverSSH(client, streamCmd, extractDir, true); err == nil {
		logger.InfoExtra(i, fmt.Sprintf("Successfully downloaded %s -> %s", remotePath, extractDir))
		return
	} else {
		logger.Debug(fmt.Sprintf("Streaming tar|gzip failed for '%s': %s, trying uncompressed...", remotePath, err))
	}

	// 3) Stream uncompressed tar (no gzip at all)
	streamCmd = fmt.Sprintf("tar cf - -C / %s 2>/dev/null", tarPath)
	if err := streamTarOverSSH(client, streamCmd, extractDir, false); err == nil {
		logger.InfoExtra(i, fmt.Sprintf("Successfully downloaded %s -> %s", remotePath, extractDir))
		return
	} else {
		logger.Debug(fmt.Sprintf("Streaming uncompressed tar failed for '%s': %s, trying file-based fallback...", remotePath, err))
	}

	// 4) File-based fallback (if streaming doesn't work — weird shells, etc.)
	downloadFallback(i, client, remotePath, tarPath, extractDir)
}

// streamTarOverSSH runs a tar command on the remote and pipes stdout directly
// into a local tar extractor. No temp files on either side.
func streamTarOverSSH(client *goph.Client, remoteCmd string, extractDir string, isGzipped bool) error {
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	stdout, err := session.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to get stdout pipe: %w", err)
	}

	if err := session.Start(remoteCmd); err != nil {
		return fmt.Errorf("failed to start command: %w", err)
	}

	var extractErr error
	if isGzipped {
		extractErr = utils.ExtractTarGzFromReader(stdout, extractDir)
	} else {
		extractErr = utils.ExtractTarFromReader(stdout, extractDir)
	}

	// Wait for session to finish regardless of extract result
	sessionErr := session.Wait()

	if extractErr != nil {
		return fmt.Errorf("extraction error: %w", extractErr)
	}
	// tar may exit non-zero on permission errors but the data is fine — only
	// fail if we got zero bytes (extractErr would have caught that)
	_ = sessionErr
	return nil
}

// downloadFallback is the old file-based approach: tar to file, SFTP download, extract locally
func downloadFallback(i Instance, client *goph.Client, remotePath string, tarPath string, extractDir string) {
	logger.InfoExtra(i, fmt.Sprintf("Downloading %s -> %s (file-based fallback)", remotePath, extractDir))

	randName := utils.GenerateRandomFileName(12)
	remoteArchive := fmt.Sprintf("/tmp/%s.tar.gz", randName)
	localArchive := filepath.Join(extractDir, fmt.Sprintf("%s.tar.gz", randName))

	archiveCmd := fmt.Sprintf("tar czf %s -C / %s 2>/dev/null; [ -s %s ]", remoteArchive, tarPath, remoteArchive)
	if _, err := client.Run(archiveCmd); err != nil {
		// Try uncompressed
		client.Run(fmt.Sprintf("rm -f %s", remoteArchive))
		remoteArchive = fmt.Sprintf("/tmp/%s.tar", randName)
		localArchive = filepath.Join(extractDir, fmt.Sprintf("%s.tar", randName))
		archiveCmd = fmt.Sprintf("tar cf %s -C / %s 2>/dev/null; [ -s %s ]", remoteArchive, tarPath, remoteArchive)
		if _, err := client.Run(archiveCmd); err != nil {
			client.Run(fmt.Sprintf("rm -f /tmp/%s.*", randName))
			logger.ErrExtra(i, fmt.Sprintf("Failed to archive '%s' on remote", remotePath))
			return
		}
	}

	err := client.Download(remoteArchive, localArchive)
	if err != nil {
		logger.ErrExtra(i, fmt.Sprintf("Failed to download archive for '%s': %s", remotePath, err))
		client.Run(fmt.Sprintf("rm -f %s", remoteArchive))
		os.Remove(localArchive)
		return
	}
	client.Run(fmt.Sprintf("rm -f %s", remoteArchive))

	extrErr := utils.ExtractTarGz(localArchive, extractDir)
	if extrErr != nil {
		extrErr = utils.ExtractTar(localArchive, extractDir)
	}
	if extrErr != nil {
		logger.ErrExtra(i, fmt.Sprintf("Failed to extract archive for '%s': %s (keeping archive)", remotePath, extrErr))
		return
	}

	os.Remove(localArchive)
	logger.InfoExtra(i, fmt.Sprintf("Successfully downloaded %s -> %s", remotePath, extractDir))
}

func Upload(client *goph.Client, localPath string, remotePath string) error {
	logger.Debug(fmt.Sprintf("Starting Upload. Local path: %s, Remote path: %s", localPath, remotePath))

	scp_client, err := scp.NewClientBySSH(client.Client)
	if err != nil {
		logger.Err(fmt.Sprintf("Failed to initialize SCP client: %s", err))
		return err
	}

	f, err := os.Open(localPath)
	if err != nil {
		logger.Err(fmt.Sprintf("Failed to open local file: %s", err))
		return err
	}
	defer f.Close()

	err = scp_client.CopyFromFile(context.Background(), *f, remotePath, "0777")
	if err != nil {
		logger.Err(fmt.Sprintf("Failed to SCP file: %s", err))
		return err
	}

	output, err := client.Run("ls " + remotePath)
	if err != nil {
		logger.Err(fmt.Sprintf("Failed to verify remote file: %s", err))
		return err
	}
	if strings.Contains(string(output), "No such file or directory") {
		logger.Err("Remote file does not exist after upload.")
		return errors.New("upload failed: remote file missing")
	}
	logger.Debug("Upload successful.")
	return nil
}

func IsValidPort(host string, port int) bool {
	logger.Debug(fmt.Sprintf("Checking if port %d is valid on host %s", port, host))

	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, 5000*time.Millisecond)
	if err != nil {
		return false
	}
	defer conn.Close()

	banner, _ := bufio.NewReader(conn).ReadString('\n')
	regex := regexp.MustCompile(`(?i)windows|winssh`)
	isValid := !regex.MatchString(banner)
	logger.Debug(fmt.Sprintf("Port %d validity on host %s: %t", port, host, isValid))
	return isValid
}
