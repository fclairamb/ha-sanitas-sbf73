"""Constants for the Sanitas SBF73 integration."""

DOMAIN = "sanitas_sbf73"

CONF_USER_INDEX = "user_index"
CONF_CONSENT_CODE = "consent_code"
CONF_LAST_TIMESTAMP = "last_timestamp"

WSS_SERVICE_UUID = "0000181d-0000-1000-8000-00805f9b34fb"

# Minimum time between two connection attempts while the scale is awake.
SYNC_COOLDOWN_S = 30
# After failed attempts, wait twice as long each time, up to this.
MAX_BACKOFF_S = 1800
# After consent, the scale sends its stored measurements. Stop listening after
# QUIET_S without a packet, and in any case after IDLE_TIMEOUT_S.
QUIET_S = 8
IDLE_TIMEOUT_S = 45
