package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/slack-go/slack"
)

func parseDN(dn string) map[string]string {
	out := make(map[string]string)
	if dn != "" {
		for _, segment := range strings.Split(dn, ", ") {
			parts := strings.SplitN(segment, "=", 2)
			if len(parts) >= 2 {
				out[parts[0]] = parts[1]
			}
		}
	}
	return out
}

func main() {

	// always present
	fingerprint := os.Getenv("FINGERPRINT")
	certType := os.Getenv("CERT_TYPE")
	certParseable := os.Getenv("CERT_PARSEABLE") // yes/no
	logUri := os.Getenv("LOG_URI")
	// entryIndex := os.Getenv("ENTRY_INDEX")
	// certFilename := os.Getenv("CERT_FILENAME") // only if storing is on

	// presence depends on lack of errors
	dnsNames := os.Getenv("DNS_NAMES") // comma-separated
	// ipAddresses := os.Getenv("IP_ADDRESSES") // comma-separated
	// pubkeyHash := os.Getenv("PUBKEY_HASH")
	// serial := os.Getenv("SERIAL")
	notBefore := os.Getenv("NOT_BEFORE")
	// notBeforeUnix := os.Getenv("NOT_BEFORE_UNIXTIME")
	notAfter := os.Getenv("NOT_AFTER")
	// notAfterUnix := os.Getenv("NOT_AFTER_UNIXTIME")
	subjectDN := os.Getenv("SUBJECT_DN")
	subjectInfo := parseDN(subjectDN)
	issuerDN := os.Getenv("ISSUER_DN")
	issuerInfo := parseDN(issuerDN)

	// aggregate all the problems that blocked fields from being read
	// CERTIFICATE - gates every variable in second block
	// IDENTIFIERS - gates DNS_NAMES, IP_ADDRESSES
	// SERIAL - gates SERIAL
	// VALIDITY - gates NOT_BEFORE, NOT_AFTER, etc
	// SUBJECT - gates SUBJECT_DN
	// ISSUER - gates ISSUER_DN
	parseErrors := make(map[string]string)
	parseErrorString := ""
	for _, e := range os.Environ() {
		pair := strings.SplitN(e, "=", 2)
		if strings.HasSuffix(pair[0], "_PARSE_ERROR") {
			errorType := strings.TrimSuffix(pair[0], "_PARSE_ERROR")
			parseErrors[errorType] = pair[1]
			parseErrorString = fmt.Sprintf("%v\n- %v: %v", parseErrorString, errorType, pair[1])
		} else if pair[0] == "PARSE_ERROR" {
			parseErrors["CERTIFICATE"] = pair[1]
			parseErrorString = fmt.Sprintf("%v\n- %v: %v", parseErrorString, "CERTIFICATE", pair[1])
		}
	}
	if parseErrorString != "" {
		parseErrorString = "\n\nSome of the certificate couldn't be parsed:" + parseErrorString
	}

	subjectName := "unknown"
	if name, ok := subjectInfo["CN"]; ok {
		subjectName = name
	}
	issuerOrg := "unknown"
	if org, ok := issuerInfo["O"]; ok {
		issuerOrg = org
	}

	certTense := "will be"
	if certType == "cert" {
		certTense = "has been"
	}

	notifTitle := fmt.Sprintf("SSL Certificate %v issued for %v by %v",
		certTense, dnsNames, issuerOrg)
	notifByline := fmt.Sprintf("Certificate Transparency log %v recorded a %v for a watched domain",
		logUri, certType)
	notifData := fmt.Sprintf("```\nIssuer: %v\nSubject: %v\nNot before: %v\nNot after: %v\nFingerprint: %v\n```",
		issuerDN, subjectDN, notBefore, notAfter, fingerprint)
	notifDataList := fmt.Sprintf("• Issuer: `%v`\n• Subject: `%v`\n• Not before: `%v`\n• Not after: `%v`\n• Fingerprint: `%v`",
		issuerDN, subjectDN, notBefore, notAfter, fingerprint)

	if datadogHost := os.Getenv("DD_AGENT_HOST"); datadogHost != "" {
		ddog, err := statsd.New(datadogHost + ":8125")
		if err != nil {
			log.Println(err)
		} else {
			_ = ddog.Event(&statsd.Event{
				Title: notifTitle,
				Text: fmt.Sprintf("%v:\n%v\n[View certificate](https://crt.sh/?q=%v)%v",
					notifByline, notifData, fingerprint, parseErrorString),
				AggregationKey: fmt.Sprintf("certspotter-%v-%v", fingerprint, certType),
				Priority:       statsd.Normal, // or Low
				SourceTypeName: "certspotter",
				AlertType:      statsd.Warning, // Info or Warning or Error or Success
				Tags: []string{
					"ct_type:" + certType,
					"ct_parseable:" + certParseable,
					"ct_issuer:" + issuerOrg,
				},
			})
			_ = ddog.Flush()
		}
	}

	if slackUrl := os.Getenv("SLACK_WEBHOOK_URL"); slackUrl != "" {
		attachment := slack.Attachment{
			Color:         "#3BB9FF",
			Fallback:      notifTitle + "\n" + notifByline,
			AuthorName:    subjectName + " " + certType,
			AuthorSubname: logUri,
			Title:         notifTitle,
			TitleLink:     "https://crt.sh/?q=" + fingerprint,
			Text:          notifDataList + parseErrorString,
		}
		if certType == "cert" {
			attachment.Color = "#357EC7"
		}

		err := slack.PostWebhook(slackUrl, &slack.WebhookMessage{
			Attachments: []slack.Attachment{attachment},
		})
		if err != nil {
			log.Println(err)
		}
	}

	log.Println(notifTitle)

	// this gives plenty of time for Datadog to flush
	// less is probably fine but this binary should only run like 4 times a week lol
	time.Sleep(time.Second)
}
