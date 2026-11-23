package ui

import (
	"time"

	"github.com/ardayesilcayir/authdiff/internal/config"
)

// Project is the UI's source of truth for one project, stored as
// project.json. It holds the wizard state, half-finished settings included,
// and never a token, user name or password: those live in Secrets.
type Project struct {
	Name         string               `json:"name"`
	Demo         bool                 `json:"demo,omitempty"`
	CreatedAt    time.Time            `json:"createdAt"`
	UpdatedAt    time.Time            `json:"updatedAt"`
	BaseURL      string               `json:"baseUrl,omitempty"`
	SpecURL      string               `json:"specUrl,omitempty"`
	SpecFile     string               `json:"specFile,omitempty"` // file name inside the project directory
	AllowHosts   []string             `json:"allowHosts,omitempty"`
	Acknowledged bool                 `json:"acknowledged,omitempty"`
	Exclude      []string             `json:"exclude,omitempty"` // "METHOD /path"
	Tags         []string             `json:"tags,omitempty"`
	Profiles     []ProfileDef         `json:"profiles,omitempty"`
	Harvest      []config.HarvestRule `json:"harvest,omitempty"`
	Safety       SafetyDef            `json:"safety"`
	Matrix       map[string][]string  `json:"matrix,omitempty"`
	IgnoreFields []string             `json:"ignoreFields,omitempty"`
	Threshold    float64              `json:"threshold,omitempty"`
	Step         string               `json:"step,omitempty"` // wizard step the user stopped at
}

// ProfileDef is a profile without its secrets.
type ProfileDef struct {
	Name        string              `json:"name"`
	Role        string              `json:"role,omitempty"`
	AuthType    string              `json:"authType,omitempty"`
	AuthName    string              `json:"authName,omitempty"`
	AuthIn      string              `json:"authIn,omitempty"`
	Owns        map[string][]string `json:"owns,omitempty"`
	Identifiers []string            `json:"identifiers,omitempty"`
}

// SafetyDef is the project's request pacing and safety settings.
type SafetyDef struct {
	Rate             float64 `json:"rate,omitempty"`
	Concurrency      int     `json:"concurrency,omitempty"`
	TimeoutSec       int     `json:"timeoutSec,omitempty"`
	AllowDestructive bool    `json:"allowDestructive,omitempty"`
	Insecure         bool    `json:"insecure,omitempty"`
	Proxy            string  `json:"proxy,omitempty"`
}
