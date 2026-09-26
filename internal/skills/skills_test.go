package skills

import "testing"

func TestBundledSkillsAreDiscoverable(t *testing.T) {
	all, err := List()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) < 3 {
		t.Fatalf("only %d skills", len(all))
	}
	for _, skill := range all {
		loaded, err := Get(skill.Name)
		if err != nil || loaded.Instructions == "" {
			t.Fatalf("skill %s: %v", skill.Name, err)
		}
	}
}
