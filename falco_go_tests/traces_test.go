package falco

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v2"
)

const (
	falcoPath                  = "./falco/usr/bin/falco"
	outputDir                  = "./output_dir/"
	outputSummaryAssertionsDir = "./output_dir/summary_assertions/"
	outputMessageAssertionsDir = "./output_dir/message_assertions/"
	configSummaryAssertionsDir = "./test_configs/summary_assertions/"
	configMessageAssertionsDir = "./test_configs/message_assertions/"
)

type messageAssertion struct {
	Name        string   `yaml:"name"`
	Args        string   `yaml:"args"`
	SummaryFile string   `yaml:"summary_file"`
	ExitStatus  int      `yaml:"exit_status"`
	Messages    []string `yaml:"messages"`
}

type summaryAssertion struct {
	Name           string            `yaml:"name"`
	Args           string            `yaml:"args"`
	SummaryFile    string            `yaml:"summary_file"`
	Detect         bool              `yaml:"detect"`
	Severities     []string          `yaml:"severities"`
	TriggeredRules map[string]uint64 `yaml:"triggered_rules"`
}

type falcoSummary struct {
	EventsDetected       uint64            `json:"eventDetected"`
	RuleCountsBySeverity map[string]uint64 `json:"ruleCountsBySeverity"`
	TriggeredRules       map[string]uint64 `json:"triggeredRules"`
}

var (
	summaryAssertions []summaryAssertion
	messageAssertions []messageAssertion
)

func setUpDirectories() error {
	if err := os.RemoveAll(outputDir); err != nil {
		return fmt.Errorf("unable to remove '%s' directory: %v\n", outputDir, err)
	}

	if err := os.MkdirAll(outputSummaryAssertionsDir, 0777); err != nil {
		return fmt.Errorf("unable to create '%s' directory: %v\n", outputSummaryAssertionsDir, err)
	}

	if err := os.MkdirAll(outputMessageAssertionsDir, 0777); err != nil {
		return fmt.Errorf("unable to create '%s' directory: %v\n", outputMessageAssertionsDir, err)
	}
	return nil
}

func TestMain(m *testing.M) {

	/* Here we need to remove the output dir and recreate necessary dirs */
	if err := setUpDirectories(); err != nil {
		log.Fatal(err)
	}

	/* Here we will download scap-files from the site */
	/// TODO

	/* Read all summary Assertions under the assertion directory */
	if err := filepath.Walk(configSummaryAssertionsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("unable to walk into '%s' path", path)
		}

		/* we don't care about directories */
		if info.IsDir() {
			return nil
		}

		yfile, err := ioutil.ReadFile(path)
		if err != nil {
			return fmt.Errorf("unable to read the config file '%s': %v", path, err)
		}

		var tmpSummaryAssertions []summaryAssertion
		err = yaml.Unmarshal(yfile, &tmpSummaryAssertions)
		if err != nil {
			return fmt.Errorf("unable to parse the config file '%s': %v", path, err)
		}

		/* Append all new assertions into the array */
		summaryAssertions = append(summaryAssertions, tmpSummaryAssertions...)

		return nil
	}); err != nil {
		log.Fatal(err)
	}

	if err := filepath.Walk(configMessageAssertionsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("unable to walk into '%s' path", path)
		}

		/* we don't care about directories */
		if info.IsDir() {
			return nil
		}

		yfile, err := ioutil.ReadFile(path)
		if err != nil {
			return fmt.Errorf("unable to read the config file '%s': %v", path, err)
		}

		var tmpMessageAssertions []messageAssertion
		err = yaml.Unmarshal(yfile, &tmpMessageAssertions)
		if err != nil {
			return fmt.Errorf("unable to parse the config file '%s': %v", path, err)
		}

		/* Append all new assertions into the array */
		messageAssertions = append(messageAssertions, tmpMessageAssertions...)

		return nil
	}); err != nil {
		log.Fatal(err)
	}

	// call flag.Parse() here if TestMain uses flags
	os.Exit(m.Run())
}

func summaryNoDetect(t *testing.T, tc summaryAssertion, stats falcoSummary) {
	/* If the map is empty we have no rules triggered, so we can return */
	if len(stats.RuleCountsBySeverity) == 0 {
		return
	}

	/* If the map is not empty we want to assert that these Severities are not triggered */
	for _, severity := range tc.Severities {
		if val, ok := stats.RuleCountsBySeverity[severity]; ok {
			t.Fatalf("Severity '%s' shouldn't be here but it counts is: %d. Look at the '%s' file to see the result capture\n", severity, val, tc.SummaryFile)
		}
	}
}

func summaryDetect(t *testing.T, tc summaryAssertion, stats falcoSummary) {
	/* If the map is empty we should fail since we expect to detect something */
	if len(stats.RuleCountsBySeverity) == 0 {
		t.Fatalf("We should detect some severities but the RuleCounts Map is empty. Look at the '%s' file to see the result capture\n", tc.SummaryFile)
	}

	for _, severity := range tc.Severities {
		if _, ok := stats.RuleCountsBySeverity[severity]; !ok {
			t.Errorf("Severity '%s' should be here but we don't have it in the map. Look at the '%s' file to see the result capture\n", severity, tc.SummaryFile)
		}
	}

	/* If we have Rule Counts we should have some triggered rules */
	if len(stats.TriggeredRules) == 0 {
		t.Fatalf("We should have some triggered rules some but the TriggeredRules Map is empty. Look at the '%s' file to see the result capture\n", tc.SummaryFile)
	}

	/* The triggeredRule map could be empty in the Test config, maybe we want to assert only the sevirity */
	for expectedRule, expectedRuleCount := range tc.TriggeredRules {
		ruleCount, ok := stats.TriggeredRules[expectedRule]

		/* The rule is not here! */
		if !ok {
			t.Errorf("Rule '%s' should be here but we don't have it in the map. Look at the '%s' file to see the result capture\n", expectedRule, tc.SummaryFile)
			continue
		}

		if expectedRuleCount != ruleCount {
			t.Errorf("Rule '%s' should occur '%d' times but the actual count is '%d'. Look at the '%s' file to see the result capture\n", expectedRule, expectedRuleCount, ruleCount, tc.SummaryFile)
		}
	}
}

func TestSummaryAssertions(t *testing.T) {
	for _, tc := range summaryAssertions {
		tc := tc // capture range variable
		t.Run(tc.Name, func(t *testing.T) {
			// t.Parallel()

			/* Run Falco with the necessary config */
			runner := exec.Command(falcoPath, strings.Fields(tc.Args)...)
			if err := runner.Run(); err != nil {
				t.Fatalf("unable to run '%s' with args '%s: %v\n", falcoPath, tc.Args, err)
			}

			/* Open and parse the Falco-generated summary file */
			jsonFile, err := os.OpenFile(tc.SummaryFile, os.O_RDONLY, 0644)
			if err != nil {
				t.Fatalf("unable to open '%s' file: %v\n", tc.SummaryFile, err)
			}
			defer jsonFile.Close()

			var byteValue []byte
			byteValue, err = ioutil.ReadAll(jsonFile)
			if err != nil {
				t.Fatalf("unable to open '%s' file: %v\n", tc.SummaryFile, err)
			}

			stats := falcoSummary{}
			err = json.Unmarshal(byteValue, &stats)
			if err != nil {
				t.Fatalf("unable to unmarshal '%s' file: %v\n", tc.SummaryFile, err)
			}

			if !tc.Detect {
				summaryNoDetect(t, tc, stats)
			} else {
				summaryDetect(t, tc, stats)
			}

		})
	}
}

func TestMessageAssertions(t *testing.T) {
	for _, ma := range messageAssertions {
		ma := ma // capture range variable
		t.Run(ma.Name, func(t *testing.T) {
			// t.Parallel()

			/* Run Falco with the necessary config */
			runner := exec.Command(falcoPath, strings.Fields(ma.Args)...)

			/* Create the file that will contain Falco stdout or stderr */
			outFile, err := os.OpenFile(ma.SummaryFile, os.O_RDWR|os.O_CREATE, 0644)
			if err != nil {
				t.Fatalf("unable to open '%s' file: %v\n", ma.SummaryFile, err)
			}
			defer outFile.Close()

			runner.Stderr = outFile

			err = runner.Run()

			if ma.ExitStatus != 0 {
				if err == nil {
					t.Fatalf("falco should fail with exit status '%d' but the run was successful\n", ma.ExitStatus)
				}

				if exitError, ok := err.(*exec.ExitError); !ok || exitError.ExitCode() != ma.ExitStatus {
					t.Fatalf("falco should fail with exit status '%d' but it fails with exit status '%d'\n", ma.ExitStatus, exitError.ExitCode())
				}
			}

			if ma.ExitStatus == 0 && err != nil {
				t.Fatalf("unable to run '%s' with args '%s: %v\n", falcoPath, ma.Args, err)
			}

			for _, message := range ma.Messages {
				outFile.Seek(0, io.SeekStart)
				scanner := bufio.NewScanner(outFile)
				found := false
				for scanner.Scan() {
					if strings.Contains(scanner.Text(), message) {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("message '%s' is not present in the output file '%s'\n", message, ma.SummaryFile)
				}
			}
		})
	}
}
