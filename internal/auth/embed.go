package auth

import _ "embed"

//go:embed keys/public.pem
var embeddedPublicKey []byte
