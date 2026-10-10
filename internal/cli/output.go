package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"text/tabwriter"
	"unicode/utf16"

	"ssmh/internal/logging"
)

type listRow struct {
	ID        string `json:"instance_id"`
	Name      string `json:"name"`
	State     string `json:"state"`
	SSM       string `json:"ssm_status"`
	Platform  string `json:"platform"`
	PrivateIP string `json:"private_ip"`
	Region    string `json:"region"`
}

func formatList(rows []listRow, machine bool) ([]byte, error) {
	var output bytes.Buffer
	if machine {
		if rows == nil {
			rows = make([]listRow, 0)
		}
		return asciiJSON(rows)
	} else {
		w := tabwriter.NewWriter(&output, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "INSTANCE ID\tNAME\tSTATE\tSSM STATUS\tPLATFORM\tPRIVATE IP\tREGION")
		for _, row := range rows {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", row.ID, logging.SafeText(row.Name), row.State, row.SSM, row.Platform, row.PrivateIP, row.Region)
		}
		if err := w.Flush(); err != nil {
			return nil, errors.New("cannot format listing table")
		}
	}
	if output.Len() > 32<<20 {
		return nil, errors.New("listing output exceeds its safety limit")
	}
	return output.Bytes(), nil
}

// asciiJSON accepts only the private, allowlisted inspection DTOs. Unicode
// escapes prevent raw formatting characters while preserving decoded values.
func asciiJSON(value any) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, errors.New("cannot format inspection JSON")
	}
	var output bytes.Buffer
	for _, r := range string(data) {
		if r <= 127 {
			output.WriteByte(byte(r))
		} else if r <= 0xffff {
			fmt.Fprintf(&output, `\u%04x`, r)
		} else {
			hi, lo := utf16.EncodeRune(r)
			fmt.Fprintf(&output, `\u%04x\u%04x`, hi, lo)
		}
	}
	output.WriteByte('\n')
	if output.Len() > 32<<20 {
		return nil, errors.New("inspection output exceeds its safety limit")
	}
	return output.Bytes(), nil
}
