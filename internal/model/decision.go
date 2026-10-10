package model

// Detection records a proposed action, separately from the final proxy outcome.
type Detection struct {
	Source string `json:"source"`
	Action string `json:"action"`
	Reason string `json:"reason"`
}
