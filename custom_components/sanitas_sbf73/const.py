"""Constants for the Sanitas SBF73 integration."""

DOMAIN = "sanitas_sbf73"

CONF_USER_INDEX = "user_index"
CONF_CONSENT_CODE = "consent_code"
CONF_LAST_TIMESTAMP = "last_timestamp"

# Manufacturer data company id seen in the scale advertisement (meaning unknown).
MANUFACTURER_ID = 0x0613

# The scale advertises all the time, so we can't connect on every advertisement.
# Connect when the advertisement changes, else at most every SYNC_INTERVAL_S.
SYNC_INTERVAL_S = 3600
SYNC_COOLDOWN_S = 60
# After consent, the scale sends its stored measurements. Stop listening after
# QUIET_S without a packet, and in any case after IDLE_TIMEOUT_S.
QUIET_S = 8
IDLE_TIMEOUT_S = 45
