//go:build linux

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
)

func controllerQuery(ctx context.Context, query string) (string, error) {
	b, e := composeCommand(ctx, deviceProject, "exec", "-T", "box-postgres", "psql", "-U", "facets_box_controller", "-d", "facets_box_controller", "-tA", "-c", query)
	return strings.TrimSpace(string(b)), e
}

// Resume only a consistent installation. The existing controller command is
// responsible for initialization; this code never inserts a Box identity row.
func initializeController(ctx context.Context, identity applianceIdentity, image string) (controllerIdentity, error) {
	var out controllerIdentity
	const record = dataRoot + "/configuration/controller-identity.json"
	_, e := os.Stat(record)
	retained := e == nil
	if e != nil && !os.IsNotExist(e) {
		return out, e
	}
	table, e := controllerQuery(ctx, "SELECT to_regclass('public.box_state') IS NOT NULL")
	if e != nil {
		return out, e
	}
	boxID := ""
	if table == "t" {
		boxID, e = controllerQuery(ctx, "SELECT box_id::text FROM box_state WHERE id = true")
		if e != nil {
			return out, e
		}
	}
	if boxID == "" && retained {
		return out, errors.New("retained controller database identity unavailable")
	}
	root, e := volumeDirectory(ctx, deviceProject+"_facets-box-controller-state", !retained && boxID == "")
	if e != nil {
		return out, e
	}
	keyPath := root + "/identity-key"
	if _, e = os.Stat(keyPath); e == nil {
		if _, e = readControllerKey(keyPath); e != nil {
			return out, e
		}
	} else if !os.IsNotExist(e) || boxID != "" {
		return out, errors.New("retained controller key unavailable")
	}
	if !retained {
		if _, e = os.Stat(keyPath); os.IsNotExist(e) {
			_, key, e := ed25519.GenerateKey(rand.Reader)
			if e != nil {
				return out, e
			}
			if e = privateWrite(keyPath, []byte(base64.RawURLEncoding.EncodeToString(key))); e != nil {
				return out, e
			}
			if e = os.Chown(keyPath, 65532, 65532); e != nil {
				return out, e
			}
		}
		key, e := readControllerKey(keyPath)
		if e != nil {
			return out, e
		}
		sum := sha256.Sum256([]byte(identity.Secrets["activation"]))
		pending := map[string]string{"installationID": identity.InstallationID, "publicKey": base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey)), "activationDigest": hex.EncodeToString(sum[:])}
		path := dataRoot + "/configuration/controller-initialization.json"
		if b, e := os.ReadFile(path); e == nil {
			var previous map[string]string
			if json.Unmarshal(b, &previous) != nil || len(previous) != len(pending) {
				return out, errors.New("invalid interrupted controller initialization")
			}
			for k, v := range pending {
				if previous[k] != v {
					return out, errors.New("controller initialization evidence changed")
				}
			}
		} else if os.IsNotExist(e) && boxID == "" {
			if e = writeJSONFile(path, pending); e != nil {
				return out, e
			}
		} else {
			return out, errors.New("controller initialization evidence unavailable")
		}
	}
	if boxID == "" {
		if e = os.Chown(root, 65532, 65532); e != nil {
			return out, e
		}
		env := map[string]string{
			"FACETS_BOX_CONTROLLER_DATABASE_URL":      "postgres://facets_box_controller:" + identity.Secrets["controller-db"] + "@box-postgres:5432/facets_box_controller?sslmode=disable",
			"FACETS_BOX_PUBLIC_URL":                   "https://" + identity.DeviceSync.Onion + "/facetsbox",
			"FACETS_DEVICE_SYNC_BOX_CONTROLLER_TOKEN": identity.Secrets["box-controller"],
			"FACETS_BOX_DEVICE_SYNC_URL":              identity.DeviceSync.Endpoint,
		}
		b, e := encodeEnvironment(env)
		if e != nil {
			return out, e
		}
		if e = os.WriteFile("/opt/fbd/controller-initialize.env", b, 0600); e != nil {
			return out, e
		}
		// stdout contains the activation code. No Docker log is created and no
		// raw output/error is forwarded to build logs or diagnostic exports.
		b, e = privateOutput(ctx, "/usr/bin/docker", "run", "--rm", "--name", "fbd-controller-initialize", "--network", deviceProject+"_controller-private", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges=true", "--log-driver", "none", "--env-file", "/opt/fbd/controller-initialize.env", "--mount", "type=volume,src="+deviceProject+"_facets-box-controller-state,dst=/var/lib/facets-box-controller", image, "initialize", "--activation-code", identity.Secrets["activation"])
		if e != nil || strings.TrimSpace(string(b)) != "Facets Box one-time activation code: "+identity.Secrets["activation"] {
			return out, errors.New("controller initialization incomplete; inspect private state")
		}
		boxID, e = controllerQuery(ctx, "SELECT box_id::text FROM box_state WHERE id = true")
		if e != nil {
			return out, e
		}
	}
	// A DB commit followed by interruption can be reconciled against the durable
	// pre-initialization key/code record above. A claimed-but-unrecorded controller
	// is inconsistent because no management route has yet been enabled.
	if !retained {
		verifier, e := controllerQuery(ctx, "SELECT activation_verifier FROM box_state WHERE id = true AND owner_verifier = ''")
		if e != nil {
			return out, e
		}
		if verifier == "" {
			return out, errors.New("unrecorded controller was already claimed")
		}
	}
	key, e := readControllerKey(keyPath)
	if e != nil {
		return out, e
	}
	return retainControllerIdentity(record, boxID, key)
}
