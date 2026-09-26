package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/client"
)

const DefaultImage = "shadow-tools:dev"
const maxOutput = 1 << 20

type Runner struct {
	client *client.Client
	image  string
}

type Result struct {
	Output   string
	ExitCode int64
}

func New(image string) (*Runner, error) {
	if image == "" {
		image = DefaultImage
	}
	cli, err := client.New(client.FromEnv)
	if err != nil {
		return nil, err
	}
	return &Runner{client: cli, image: image}, nil
}

func (r *Runner) Close() error { return r.client.Close() }

func (r *Runner) Ping(ctx context.Context) error {
	_, err := r.client.Ping(ctx, client.PingOptions{})
	return err
}

func (r *Runner) CheckImage(ctx context.Context) error {
	_, err := r.client.ImageInspect(ctx, r.image)
	return err
}

func (r *Runner) Run(ctx context.Context, args []string, workspace string) (Result, error) {
	if len(args) == 0 {
		return Result{}, errors.New("empty command")
	}
	for _, arg := range args {
		if strings.ContainsRune(arg, 0) {
			return Result{}, errors.New("NUL in command")
		}
	}
	var mounts []mount.Mount
	if workspace != "" {
		abs, err := filepath.Abs(workspace)
		if err != nil {
			return Result{}, err
		}
		abs, err = filepath.EvalSymlinks(abs)
		if err != nil {
			return Result{}, err
		}
		if filepath.Dir(abs) == abs {
			return Result{}, errors.New("mounting a filesystem root is forbidden")
		}
		stat, err := os.Stat(abs)
		if err != nil || !stat.IsDir() {
			return Result{}, errors.New("workspace must be an existing directory")
		}
		mounts = append(mounts, mount.Mount{Type: mount.TypeBind, Source: abs, Target: "/workspace", ReadOnly: true})
	}
	pids := int64(128)
	cfg := &container.Config{
		Image:        r.image,
		Cmd:          args,
		User:         "65534:65534",
		WorkingDir:   "/workspace",
		AttachStdout: true,
		AttachStderr: true,
		Tty:          true,
	}
	host := &container.HostConfig{
		NetworkMode:    "none",
		ReadonlyRootfs: true,
		CapDrop:        []string{"ALL"},
		SecurityOpt:    []string{"no-new-privileges"},
		Tmpfs:          map[string]string{"/tmp": "rw,nosuid,nodev,size=64m"},
		Mounts:         mounts,
		Resources:      container.Resources{Memory: 512 << 20, NanoCPUs: 1_000_000_000, PidsLimit: &pids},
	}
	created, err := r.client.ContainerCreate(ctx, client.ContainerCreateOptions{Config: cfg, HostConfig: host})
	if err != nil {
		return Result{}, err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = r.client.ContainerRemove(cleanup, created.ID, client.ContainerRemoveOptions{Force: true, RemoveVolumes: true})
	}()
	if _, err := r.client.ContainerStart(ctx, created.ID, client.ContainerStartOptions{}); err != nil {
		return Result{}, err
	}
	wait := r.client.ContainerWait(ctx, created.ID, client.ContainerWaitOptions{Condition: container.WaitConditionNotRunning})
	var code int64
	select {
	case status := <-wait.Result:
		code = status.StatusCode
	case err := <-wait.Error:
		if err == nil {
			err = errors.New("container wait failed")
		}
		return Result{}, err
	case <-ctx.Done():
		return Result{}, ctx.Err()
	}
	logs, err := r.client.ContainerLogs(ctx, created.ID, client.ContainerLogsOptions{ShowStdout: true, ShowStderr: true})
	if err != nil {
		return Result{}, err
	}
	defer logs.Close()
	b, err := io.ReadAll(io.LimitReader(logs, maxOutput+1))
	if err != nil {
		return Result{}, err
	}
	if len(b) > maxOutput {
		return Result{}, fmt.Errorf("sandbox output exceeded %d bytes", maxOutput)
	}
	return Result{Output: string(b), ExitCode: code}, nil
}
