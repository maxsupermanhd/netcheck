package frontend

import (
	"main/lib/netcheck"
)

// colorForResult maps a check result to a CSS color string.
func colorForResult(c netcheck.CheckResult) string {
	if c.Color != "" {
		switch c.Color {
		case "green":
			return "#2ecc71"
		case "red":
			return "#e74c3c"
		case "orange":
			return "#e67e22"
		case "yellow":
			return "#f1c40f"
		case "gray":
			return "#7f8c8d"
		case "black":
			return "#34495e"
		default:
			return c.Color
		}
	}
	switch {
	case c.Success > 0:
		return "#2ecc71"
	case c.Success < 0:
		return "#e74c3c"
	default:
		return "#7f8c8d"
	}
}

// colorsForEndpoint returns the CSS color of every check for one endpoint,
// in the same order as checks. Two endpoints with the same per-check colors
// produce the same slice, so sequences can be deduplicated.
func colorsForEndpoint(er netcheck.EndpointResults, checks []netcheck.Check) []string {
	n := len(checks)
	cols := make([]string, n)
	for i, ch := range checks {
		col := "#202830"
		if res, ok := er.Results[ch.Name]; ok {
			col = colorForResult(res)
		}
		cols[i] = col
	}
	return cols
}

// labelFor returns the display name of an endpoint.
func labelFor(ep netcheck.EndpointDescription) string {
	if ep.Alias != "" {
		return ep.Alias
	}
	return ep.Endpoint
}

// summaryBtnClass returns the css class for the summary toggle button.
func summaryBtnClass(on bool) string {
	if on {
		return "summaryBtn active"
	}
	return "summaryBtn"
}

// statusWord returns a short status word for a check result.
func statusWord(c netcheck.CheckResult) string {
	switch {
	case c.Success > 0:
		return "OK"
	case c.Success < 0:
		return "FAIL"
	default:
		return "INC"
	}
}
