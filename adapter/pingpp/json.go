package pingpp

import "github.com/SiriusScan/scribe/internal/jsonwire"

func validateWire(data []byte) error { return jsonwire.Validate(data) }
