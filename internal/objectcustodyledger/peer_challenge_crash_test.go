package objectcustodyledger

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/robreuss/FacetsNode/internal/objectcustodyfiles"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

type peerCrashInput struct {
	Action, Point, Root, Schema, RegistryPath string
	PoolID                                    uuid.UUID
	Source                                    serviceauthority.RequestBinding
	Intent                                    serviceauthority.CustodyPeerRequest
	Proof                                     serviceauthority.CustodyPeerProof
	Body                                      []byte
}

func TestPeerChallengeAbruptHelper(t *testing.T) {
	path := os.Getenv("FACETS_PEER_CRASH_FIXTURE")
	if path == "" {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var input peerCrashInput
	if json.Unmarshal(data, &input) != nil {
		t.Fatal("invalid crash fixture")
	}
	ctx := context.Background()
	config, err := pgxpool.ParseConfig(os.Getenv("FACETS_OBJECT_CUSTODY_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	if config.ConnConfig.Database != "facets_immutable_custody_tests" {
		t.Fatal("wrong disposable database")
	}
	config.ConnConfig.RuntimeParams["search_path"] = input.Schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	files, err := objectcustodyfiles.Open(input.Root)
	if err != nil {
		t.Fatal(err)
	}
	defer files.Close()
	l, err := Open(ctx, pool, input.PoolID, files, &testCapacity{available: 90 << 30})
	if err != nil {
		t.Fatal(err)
	}
	l.fault = func(point string) error {
		if point == input.Point {
			if err := syscall.Kill(os.Getpid(), syscall.SIGKILL); err != nil {
				t.Fatal(err)
			}
			select {} // SIGKILL request can return before delivery; never advance.
		}
		return nil
	}
	switch input.Action {
	case "issue":
		_, err = l.IssuePeerChallenge(ctx, input.Source, input.Intent)
	case "consume", "reconcile":
		registry, loadErr := serviceauthority.LoadBindingRegistry(input.RegistryPath, input.Source.DeploymentID)
		if loadErr != nil {
			t.Fatal(loadErr)
		}
		defer registry.Close()
		if input.Action == "reconcile" {
			err = l.ReconcilePeerAuthority(ctx, registry, input.Source.Scope)
		} else {
			_, err = l.VerifyPeerChallenge(ctx, registry, input.Intent.Target.BindingID, input.Intent.OperationID, input.Proof, input.Body)
		}
	default:
		t.Fatal("unexpected crash action")
	}
	t.Fatalf("abrupt boundary not reached: %v", err)
}

func TestPeerChallengeActualProcessTermination(t *testing.T) {
	for _, action := range []string{"issue", "consume", "reconcile"} {
		for _, point := range []string{"before_database_commit", "after_database_commit"} {
			t.Run(action+"/"+point, func(t *testing.T) {
				f := newPeerFixture(t)
				ctx := context.Background()
				input := peerCrashInput{Action: action, Point: point, Root: f.f.path, Schema: f.f.pool.Config().ConnConfig.RuntimeParams["search_path"], RegistryPath: f.receiverPath, PoolID: f.f.l.poolID, Source: f.source, Intent: f.intent, Body: f.body}
				if action == "consume" {
					input.Proof = f.sign(t, f.issue(t))
				}
				if action == "reconcile" {
					if _, err := f.f.pool.Exec(ctx, `DELETE FROM immutable_custody_peer_authorities`); err != nil {
						t.Fatal(err)
					}
				}
				encoded, err := json.Marshal(input)
				if err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(t.TempDir(), "peer-crash.json")
				if err = os.WriteFile(path, encoded, 0o600); err != nil {
					t.Fatal(err)
				}
				if err = f.f.files.Close(); err != nil {
					t.Fatal(err)
				}
				if err = f.receiver.Close(); err != nil {
					t.Fatal(err)
				}
				command := exec.Command(os.Args[0], "-test.run=^TestPeerChallengeAbruptHelper$")
				command.Env = append(os.Environ(), "FACETS_PEER_CRASH_FIXTURE="+path)
				output, runErr := command.CombinedOutput()
				var exitErr *exec.ExitError
				if !errors.As(runErr, &exitErr) {
					t.Fatalf("not a killed process: %v %s", runErr, output)
				}
				status, ok := exitErr.Sys().(syscall.WaitStatus)
				if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
					t.Fatalf("wrong process exit: %v %s", runErr, output)
				}
				files, err := objectcustodyfiles.Open(f.f.path)
				if err != nil {
					t.Fatal(err)
				}
				defer files.Close()
				f.f.files = files
				f.f.l, err = Open(ctx, f.f.pool, input.PoolID, files, f.f.provider)
				if err != nil {
					t.Fatal(err)
				}
				f.receiver, err = serviceauthority.LoadBindingRegistry(f.receiverPath, f.source.DeploymentID)
				if err != nil {
					t.Fatal(err)
				}
				defer f.receiver.Close()
				if action == "reconcile" {
					_, err := loadPeerAuthority(ctx, f.f.pool, f.source.Scope)
					if point == "before_database_commit" && !errors.Is(err, pgx.ErrNoRows) {
						t.Fatal("uncommitted authority survived process kill", err)
					}
					if point == "after_database_commit" && err != nil {
						t.Fatal("committed authority lost after process kill", err)
					}
					if err := f.f.l.ReconcilePeerAuthority(ctx, f.receiver, f.source.Scope); err != nil {
						t.Fatal("authority restart reconciliation", err)
					}
					if _, err := f.verify(f.sign(t, f.issue(t)), f.body); err != nil {
						t.Fatal("authority restart challenge", err)
					}
					return
				}
				current, err := loadPeerChallenge(ctx, f.f.pool, f.f.binding.ID, f.intent.OperationID)
				if action == "issue" && point == "before_database_commit" {
					if !errors.Is(err, pgx.ErrNoRows) {
						t.Fatalf("uncommitted issuance survived: %v", err)
					}
				} else if err != nil || current.Consumed != (action == "consume" && point == "after_database_commit") {
					t.Fatalf("wrong retained boundary: %v", err)
				}
				c := f.issue(t)
				proof := input.Proof
				if action == "issue" {
					proof = f.sign(t, c)
				}
				if _, err = f.verify(proof, f.body); err != nil {
					t.Fatal("restart retry failed", err)
				}
			})
		}
	}
}
