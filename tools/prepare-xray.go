//go:build ignore

// 按 Xray 版本准备构建依赖，仅对绑定版本应用既有 TLS 补丁。
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"go/format"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

func main() {
	if err := prepare(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func prepare() error {
	if len(os.Args) != 2 {
		return fmt.Errorf("用法：go run ./tools/prepare-xray.go <独立构建目录>")
	}
	output, err := filepath.Abs(os.Args[1])
	if err != nil {
		return err
	}
	download := exec.Command("go", "mod", "download", "github.com/xtls/xray-core")
	download.Stdout, download.Stderr = os.Stdout, os.Stderr
	if err := download.Run(); err != nil {
		return fmt.Errorf("下载 Xray 源码：%w", err)
	}
	metadata, err := exec.Command("go", "list", "-mod=readonly", "-m", "-json", "github.com/xtls/xray-core").Output()
	if err != nil {
		return fmt.Errorf("读取 Xray 模块信息：%w", err)
	}
	var module struct {
		Dir, Version string
		Replace      *json.RawMessage
	}
	if err := json.Unmarshal(metadata, &module); err != nil {
		return err
	}
	if module.Version == "" || module.Replace != nil {
		return fmt.Errorf("构建必须使用 go.mod 指定的官方 Xray 模块")
	}
	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}
	for _, protected := range []string{workingDir, module.Dir} {
		relative, err := filepath.Rel(protected, output)
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return fmt.Errorf("构建目录必须位于仓库与官方模块目录之外")
		}
	}
	if err := os.MkdirAll(output, 0755); err != nil {
		return err
	}
	for _, name := range []string{"go.mod", "go.sum"} {
		data, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(output, name), data, 0644); err != nil {
			return err
		}
	}
	patchPath := filepath.Join(workingDir, "patches", "xray-tls-config.patch")
	if module.Version != "v1.260327.1-0.20261021115930-1b1647cd9ddf" {
		patch, err := os.ReadFile(patchPath)
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("读取旧 TLS 补丁：%w", err)
		}
		if err == nil {
			patch = bytes.ReplaceAll(patch, []byte("\r\n"), []byte("\n"))
			if fmt.Sprintf("%x", sha256.Sum256(patch)) != "d2b2b924662f4e982bd396eceae4bfc7cabf9e9aef3d17ef14200ca6f53090bf" {
				return fmt.Errorf("旧 TLS 补丁内容已改动，拒绝自动删除：%s", patchPath)
			}
			if err := os.Remove(patchPath); err != nil {
				return fmt.Errorf("删除旧 TLS 补丁：%w", err)
			}
		}
		fmt.Printf("Xray %s：已停用旧 TLS 补丁并清理补丁文件，使用官方内核。\n", module.Version)
		return nil
	}
	patch, err := os.ReadFile(patchPath)
	if err != nil {
		return err
	}
	patch = bytes.ReplaceAll(patch, []byte("\r\n"), []byte("\n"))
	sourceHashes := map[string]string{
		"transport/internet/tls/config.go": "159270ac6ce0bc87f48b29acdddf3676349d3b8c0ec5f183be4397ed8e69d8e8",
	}
	sections := bytes.Split(patch, []byte("--- a/"))
	if len(sections) != len(sourceHashes)+1 {
		return fmt.Errorf("TLS 补丁文件数量与绑定基线不一致")
	}
	patchedFiles := make(map[string][]byte, len(sourceHashes))
	for _, section := range sections[1:] {
		header := strings.SplitN(string(section), "\n", 3)
		name := header[0]
		hash, known := sourceHashes[name]
		if !known || patchedFiles[name] != nil || len(header) < 3 || header[1] != "+++ b/"+name {
			return fmt.Errorf("无效的 TLS 补丁文件：%s", name)
		}
		source, err := os.ReadFile(filepath.Join(module.Dir, filepath.FromSlash(name)))
		if err != nil {
			return err
		}
		source = bytes.ReplaceAll(source, []byte("\r\n"), []byte("\n"))
		if fmt.Sprintf("%x", sha256.Sum256(source)) != hash {
			return fmt.Errorf("Xray TLS 源文件与补丁基线不一致，停止构建：%s", name)
		}
		patched, err := applyPatch(source, section)
		if err != nil {
			return err
		}
		patchedFiles[name], err = format.Source(patched)
		if err != nil {
			return err
		}
	}
	localModule := filepath.Join(output, "xray-core")
	if err := filepath.WalkDir(module.Dir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(module.Dir, path)
		if err != nil {
			return err
		}
		target := filepath.Join(localModule, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0644)
	}); err != nil {
		return err
	}
	for name, patched := range patchedFiles {
		if err := os.WriteFile(filepath.Join(localModule, filepath.FromSlash(name)), patched, 0644); err != nil {
			return err
		}
	}
	command := exec.Command("go", "mod", "edit", "-modfile="+filepath.Join(output, "go.mod"), "-replace=github.com/xtls/xray-core="+localModule)
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	if err := command.Run(); err != nil {
		return err
	}
	fmt.Printf("Xray %s：已应用当前绑定版本的 TLS 补丁。\n", module.Version)
	return nil
}

func applyPatch(source, patch []byte) ([]byte, error) {
	lines := strings.SplitAfter(string(source), "\n")
	patchLines := strings.SplitAfter(strings.ReplaceAll(string(patch), "\r\n", "\n"), "\n")
	var result strings.Builder
	cursor, hunks := 0, 0
	for index := 0; index < len(patchLines); index++ {
		line := patchLines[index]
		if !strings.HasPrefix(line, "@@ ") {
			continue
		}
		fields := strings.Fields(line)
		start, err := strconv.Atoi(strings.Split(strings.TrimPrefix(fields[1], "-"), ",")[0])
		if err != nil || start < cursor+1 || start > len(lines) {
			return nil, fmt.Errorf("无效的 TLS 补丁位置：%s", line)
		}
		result.WriteString(strings.Join(lines[cursor:start-1], ""))
		cursor = start - 1
		hunks++
		for index+1 < len(patchLines) {
			line = patchLines[index+1]
			if len(line) == 0 || (line[0] != ' ' && line[0] != '+' && line[0] != '-') {
				break
			}
			index++
			if line[0] != '+' {
				if cursor >= len(lines) || lines[cursor] != line[1:] {
					return nil, fmt.Errorf("TLS 补丁第 %d 行上下文不匹配", cursor+1)
				}
				cursor++
			}
			if line[0] != '-' {
				result.WriteString(line[1:])
			}
		}
	}
	if hunks == 0 {
		return nil, fmt.Errorf("TLS 补丁没有修改内容")
	}
	result.WriteString(strings.Join(lines[cursor:], ""))
	return []byte(result.String()), nil
}
