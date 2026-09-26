package skills

import (
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"sort"
)

//go:embed data/*.json
var bundled embed.FS

type Skill struct {
	Name         string `json:"name"`
	Description  string `json:"description"`
	Instructions string `json:"instructions"`
}

func List() ([]Skill, error) {
	entries, err := fs.Glob(bundled, "data/*.json")
	if err != nil {
		return nil, err
	}
	var out []Skill
	seen := map[string]bool{}
	for _, path := range entries {
		body, err := bundled.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var skill Skill
		if err := json.Unmarshal(body, &skill); err != nil {
			return nil, err
		}
		if skill.Name == "" || skill.Description == "" || skill.Instructions == "" || seen[skill.Name] {
			return nil, errors.New("invalid or duplicate bundled skill")
		}
		seen[skill.Name] = true
		out = append(out, skill)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func Get(name string) (Skill, error) {
	all, err := List()
	if err != nil {
		return Skill{}, err
	}
	for _, skill := range all {
		if skill.Name == name {
			return skill, nil
		}
	}
	return Skill{}, errors.New("skill not found")
}
