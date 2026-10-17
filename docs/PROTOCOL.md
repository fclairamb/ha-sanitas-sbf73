# Sanitas SBF73 BLE protocol (from Sanitas HealthCoach 3.0.1)

Source: static analysis of `de.sanitas_online.healthcoach` v3.0.1 (versionCode 2025111101,
APK sha256 `f6f5ad4823e17f9d632b65f3379ea1df7b5ede1485ae298b05f284d6f9170243`). The APK was
never installed or run. Cross-checked against openScale `SanitasSbf72Handler.kt` +
`StandardWeightProfileHandler.kt`.

Conventions:

- File references are relative to the JADX tree `jadx-out/sources/`. Abbreviations:
  `BLA` = `com/ilink/bleapi/BluetoothLeApi.java`, `BA` = `com/impirion/deviceClass/ble/BleApi.java`,
  `GDH` = `com/beurer/connect/healthmanager/data/datahelper/GewichtDataHelper.java`,
  `SS` = `com/ilink/bleapi/SupportedServices.java`, `UI/` = `com/impirion/deviceClass/scale/ble/`.
- **CONFIRMED** = seen in the app code. **INFERRED** = deduced (from the code's assumptions, the
  Bluetooth SIG spec, or openScale), not directly proven by the app.
- All multi-byte integers are little-endian. "Write" means GATT Write Request (with response);
  the app always waits for `onCharacteristicWrite` before the next step.
- The app treats SBF72 and SBF73 with one code path. Differences are listed in section 7.

REA evidence (inspect-android-method, provider JADX headless 0.7.1, outputs in `rea-out/m-*.json`):

| Method (dex descriptor) | evidence_id (prefix) |
|---|---|
| `BluetoothLeApi.writeAllDescriptor()V` | `ev_e10e5d9898bdf99c` |
| `BluetoothLeApi.setDescriptor(BluetoothGattCharacteristic)Z` | `ev_9508914c0f9acb1c` |
| `BluetoothLeApi.writeCurrentTime(String,Gatt,Char,Date)V` | `ev_a46656ba47463b7d` |
| `BluetoothLeApi.writeUcpRegisterUser(String,Gatt,Char,I)V` | `ev_d23929ce3602712a` |
| `BluetoothLeApi.writeUcpConsentCode(String,Gatt,Char,II)V` | `ev_99d3cc097c3221b4` |
| `BluetoothLeApi.writeUcpDeleteUser(String,Gatt,Char)V` | `ev_63282562c58e884d` |
| `BluetoothLeApi.showConsentCodeForExistingUser(String,I)Z` | `ev_f1e8835b1f8c6d98` |
| `BluetoothLeApi.readUserList()V` | `ev_1f4bfe348d34236f` |
| `BluetoothLeApi.writeDateOfBirth(...)Z` | `ev_af1bbc031f6337dc` |
| `BluetoothLeApi.writeHeight(...)V` | `ev_c1f8785c6403478f` |
| `BluetoothLeApi.writeUserInitials(...)V` | `ev_69629b9970d5771e` |
| `BluetoothLeApi.writeDatabaseChangeIncrement(...J)V` | `ev_e86a4a9e2be60fb4` |
| `BluetoothLeApi.writeScaleSetting(...)V` | `ev_688df299d80b1610` |
| `BluetoothLeApi.writeTakeMeasurement()V` | `ev_486f4138a63ce05f` |
| `BluetoothLeApi.AnonymousClass5.onCharacteristicChanged(Gatt,Char)V` | `ev_5faee87c5f1248ab` |
| `BleApi.createNewUser(String)V` | `ev_a44b698b7d3a75ef` |
| `BleApi.setScaleCurrentUserData([B)V` | `ev_f68a3c74295af6eb` |
| `GewichtDataHelper.insertMeasurementReceivedByScale(I,ReceivedMeasurementPackage,I)I` | `ev_7dae30f6a9a3c2ee` |
| `Utilities.calculateMifflinBMRWithWeightKG(DZ)I` | `ev_31c229ab48d3489b` |

REA `trace-android-references` confirms the callers: `writeUcpConsentCode` is called from
`checkAndReAttempt`, `deleteUser`, `reConnectService` (`ev_c5600a1f4a3f31ab`);
`insertMeasurementReceivedByScale` only from `BleApi.insertMeasurement` (`ev_61b5d75f400bc4dd`);
`showConsentCodeForExistingUser` only from `BleApi.showConsentCodeForExistingUser` (`ev_0ba0e8d846d17b73`).

---

## 1. Discovery

### 1.1 Name match — CONFIRMED

- Scale names come from the app DB table `BeurerDevices` (DeviceClass 3). SBF73 row:
  `DeviceName = 'SBF73'`, and in `Devices`: `NoOfSupportedUsers = 8`
  (`assets/databases/Healthcoach.db_upgrade_15-16.sql`). Constant `BleConstants.SANITAS_SBF73 = "SBF73"`
  (`com/ilink/bleapi/BleConstants.java:25`).
- Scan callback (`BLA:1436-1445`): name = `ScanRecord.getDeviceName()` (AD type 0x09 local name),
  else `BluetoothDevice.getName()`, else AD type 9 parsed by hand; `trim()`; if length == 16 it is
  cut to 12 chars, if length > 14 cut to 14. Then **exact, case-sensitive** `list.contains(name)`,
  i.e. the advertised name must be exactly `SBF73`.
- The SBF72/SBF73 branch then tests `device.getName().equalsIgnoreCase("SBF73")` (`BLA:1490`).
- Scanning is unfiltered (`startScan(new ArrayList(), ...)`, `BLA:1651/1665`), scan mode
  `SCAN_MODE_LOW_LATENCY` (2) (`BLA:1593-1595`), restarted every 6 s after a 2 s delay (`BLA:1690`).

### 1.2 Advertisement status byte (0xA5xx service UUID) — CONFIRMED parsing, INFERRED meaning

Note: the real idle SBF73 does not advertise such a UUID (see 1.4). The logic below is what the app
would do if it did.

- A scan result with **no service UUID list is ignored** (`BLA:1446-1451`).
- For SBF72/SBF73 the app looks for a 16-bit service UUID of the form `0xA5nn`
  (`uuid.charAt(4)=='a' && charAt(5)=='5'`, i.e. `0000a5nn-0000-1000-8000-00805f9b34fb`) and takes
  `nn` as the **advertisement byte** (`BLA:1511-1517`, `ScaleUtilities.getAdvertisementByte` hex decode,
  `com/ilink/bleapi/ScaleUtilities.java:856-872`).
- Decoding (`BLA:1533-1553`):

  | bits | meaning (app's own log labels) |
  |---|---|
  | bit 0 (`b % 4 in {1,3}`) | "Known measurement on device" |
  | bit 1 (`b % 4 in {2,3}`) | "Unknown measurement on device" (not assigned to a user) |
  | bit 2 (`b & 0x04`) | "Pairing bit" |
  | bits 3-7 (`b / 8`) | "No of unknown measurement on device" |

  Examples: `0000a504-…` = pairing bit only; `0000a501-…` = a known (user) measurement is stored;
  `0000a51a-…` = unknown measurements present, count 3.
- Manufacturer data is **not** parsed (only `AdvertisementRecord` types for name/UUIDs/service data exist,
  `com/ilink/bleapi/AdvertisementRecord.java:10-26`). See 1.4.
- `advertisementByte` is an **instance field** of `BluetoothLeApi` (`BLA:115`) that is only overwritten when
  a `0xA5nn` UUID is present. If the scale does not advertise one, the value from the last device that did
  is reused, and it is 0 (Java default) if none ever did. CONFIRMED (no reset anywhere).

### 1.3 When the app connects — CONFIRMED

- Low level, untrusted scale: connect if `advertisementByte == 4` exactly (pairing bit and nothing else)
  and fewer than 50 trusted devices (`BLA:1523-1528`).
- Pairing screens (`UI/sbf73/SBF73PairingScaleSelectionList.java:394-421`,
  `UI/SBF7xPairingInstructionScreen.java:619-646`): on `SBF73ScaleFound` they stop scanning and
  `forceConnect()`; if an SBF73 is already trusted, only the same MAC is accepted.
- Background/dashboard mode (`BA:571-603`): connect only if the MAC is trusted for the app user
  **and the pairing bit is 0**. The "known measurement" bit is *not* checked for SBF72/73 (it is for SBF70).
- `connectGatt(context, autoConnect=false, cb)` (`BLA:1755`). GATT status 133 → `forceConnect` again,
  up to 4 times (`BLA:343-361`).

### 1.4 The real SBF73 advertisement, and when the app connects

Observed on a real SBF73 (idle, nobody on it, 01:42), via `bluetoothctl`:

| field | value |
|---|---|
| Name | `SBF73` |
| Address | `F6:13:F7:E4:90:C5` (public) |
| Appearance | `0x0C80` (Generic Weight Scale) |
| Flags | `0x06` (LE General Discoverable, BR/EDR not supported) |
| 16-bit service UUIDs | `0x181D` only |
| Manufacturer data | company `0x0613`, value `01 00` |
| RSSI | −77 dBm |
| Behaviour | advertises continuously, even idle |

How the app reads that advertisement (CONFIRMED by exhaustive search):

- **Manufacturer data is ignored.** There is no call to `ScanRecord.getManufacturerSpecificData()`
  anywhere in the APK, no constant `0x0613` / `1555`, and `AdvertisementRecord` has no handler for AD type
  `0xFF` (`AdvertisementRecord.java:10-26, 95-134`). `SBF73ScannedDeviceInfo.getAdvertisementRecords()` is
  never read for SBF73 (the `ScaleDeviceFound` event that carries the records is only consumed by SBF70
  screens: `UI/SBF70PairingInstructionScreen.java:686`, `UI/SBF70RemoveDevice.java:778`). So the app gives
  `01 00` no meaning; nothing in the code tells what it is. INFERRED: worth logging in HA across states
  (idle, just measured, pairing) to learn whether it flags a pending measurement.
- The `0x181D` UUID satisfies the "service UUID list must not be empty" check (`BLA:1446-1451`).
- There is no `0xA5nn` UUID, so `advertisementByte` keeps its stale/default value (normally 0): pairing bit
  = 0, "known/unknown measurement" = 0. Consequences:
  - the low-level "auto-connect an untrusted scale in pairing mode" rule (`== 4`, `BLA:1523`) never fires;
  - pairing works through the UI path only: the pairing screens clear `BleApi.allScaleList` before scanning
    (`SBF73PairingScaleSelectionList.java:332`), so the **first** SBF73 advertisement seen produces a
    `SBF73ScaleFound` event (`BA:784-842`, new entry ⇒ notify) and the screen connects;
  - in background/overview mode the "pairing bit must be 0" condition is always true.

What triggers a connection to an already paired SBF73 (CONFIRMED):

- Scanning only runs while the app is in the **foreground**: `BaseFragmentActivity.onResume` →
  `startScanning()` (`com/impirion/deviceClass/dashboard/BaseFragmentActivity.java:211-263`), `onPause` →
  `stopScanning()` (`…:170-203`). There is no background service or job doing BLE (the only services are
  `ApplicationStatusService` and `NotificationCheckService`, no BLE code). So "sync" = the user opens the app.
- `scaleFoundWithname` runs for **every** scan result (`BLA:1559-1560`). Dashboard (mode 0, `BA:571-603`) or
  weight screen (mode 2, `BA:689-733`): if the MAC is the trusted SBF73, the pairing bit is 0, the device is
  not already connected and `isFirstTime == false`, the app calls `forceConnect()` and sets
  `isFirstTime = true`. No flag change, RSSI or "measurement pending" condition is required.
- `isFirstTime` is reset in `didDisconnect`, `disconnectDevice`, `forceDisconnect` (`BA:866-882, 1402`), and
  `TabbedActivity` restarts the scan after every SBF73 disconnect (`TabbedActivity.java:1523-1529`). The app
  never disconnects on its own after a dashboard sync. So while the app is open it reconnects to the next
  advertisement after each disconnect, with **no cool-down** (the stored `LastConnectionTimeStamp` is only
  displayed, never compared). The scan itself restarts every 6 s (`BLA:1690`).

Recommended Home Assistant policy (INFERRED, since the app gives no better trigger):

1. Do not connect on every advertisement. Use a cool-down (for example one sync per 15-30 min) plus an
   on-demand "sync now" service.
2. Track the manufacturer data bytes and the advertised UUID list; connect immediately when they change
   (for example a value other than `01 00`, or a `0xA5nn` UUID appearing, whose bit 0 would mean "known
   measurement stored" per 1.2). Verify on the real scale whether stepping on it changes them.
3. Measurements stay stored on the scale and are delivered after Consent (section 5), so a periodic sync
   does not lose data; it only delays it.
4. Keep the connection short: consent, collect indications for a few seconds, read battery, disconnect.

### 1.5 SBF73PairingScaleSelectionList / SBF73ScannedDeviceInfo vs SBF72 — CONFIRMED

- `SBF73ScannedDeviceInfo` is byte-identical to `SBF72ScannedDeviceInfo` except the package
  (diff shows only line 1). It is a plain holder (device, rssi, adv records).
- `SBF73PairingScaleSelectionList` is a dedicated "select / search / remove scale" screen for SBF73
  (SBF72 goes straight to `SBF7xPairingInstructionScreen`). BLE-wise it does the same: disconnect,
  `startScanning()`, connect on `SBF73ScaleFound`, then on `SBF73ConnectionCompleted` opens
  `SBF7xCreateNewUserScreen` (`SBF73PairingScaleSelectionList.java:456-500`). No extra filter.

---

## 2. GATT map

### 2.0 GATT table read from a real SBF73 (2026-10-17) — OBSERVED

| Service | Characteristics (properties) |
|---|---|
| 0x181C User Data | 0x2A8E Height (r,w), 0x2A8C Gender (r,w), 0x2A85 Date of Birth (r,w), 0x2A9A User Index (r), 0x2A9F UCP (w,indicate), 0x2A99 DB Change Increment (r,w,notify) |
| 0x180F Battery | 0x2A19 (r) |
| 0x1805 Current Time | 0x2A2B (r,w,notify) |
| **0xFFFF vendor** | 0x0006 (r,w,notify), 0x0002 (r,w), 0x000B (r), 0x0004 (r,w), 0x0000 (r,w), 0x0005 "TCS-BIN" (r,w), 0x0001 (r,w,notify) |
| 0x1801 GATT | 0x2A05 Service Changed (indicate) |
| 0x181D Weight Scale | 0x2A9D (indicate), 0x2A9E (r) |
| 0x1800 GAP | 0x2A01, 0x2A02, 0x2A03, 0x2A04, 0x2A00 |
| 0x180A Device Information | 0x2A24, 0x2A29, 0x2A26, 0x2A27, 0x2A28, 0x2A2A |
| 0xFF00 vendor | 0xFF01 (r,w,write-without-response) |
| 0x181B Body Composition | 0x2A9C (indicate), 0x2A9B (r) |

This settles open question 2: the custom `0000000x` characteristics live under service `0xFFFF`.
Reading Height (0x2A8E) without consent fails with ATT error 0x0E (Unlikely Error) and the scale drops
the link. An idle scale refuses BlueZ pairing (`AuthenticationFailed`) without asking for a passkey.


The app does **not** look services up by UUID for SBF72/73. It walks *all* services and assigns
characteristics by UUID only (`BLA:1882-1937`). So the service holding `0000000x` is irrelevant to it.

| Characteristic | UUID | Service (INFERRED unless noted) | App use | CCCD set by app |
|---|---|---|---|---|
| Current Time | 0x2A2B | 0x1805 Current Time | write 10 B; read parse | **notify** |
| Weight Measurement | 0x2A9D | 0x181D Weight Scale | indications | **indicate** |
| Weight Scale Feature | 0x2A9E | 0x181D | discovered, never read | – |
| Body Composition Measurement | 0x2A9C | 0x181B Body Composition | indications | **indicate** |
| Body Composition Feature | 0x2A9B | 0x181B | discovered, never read | – |
| Date of Birth | 0x2A85 | 0x181C User Data | write 4 B | – |
| Gender | 0x2A8C | 0x181C | write 1 B | – |
| Height | 0x2A8E | 0x181C | write **1 B** | – |
| Database Change Increment | 0x2A99 | 0x181C | read / write 4 B | **notify** (notifications ignored) |
| User Index | 0x2A9A | 0x181C | mapped, never used | – |
| User Control Point | 0x2A9F | 0x181C | write / indications | **indicate** |
| Scale Setting (custom) | `00000000-0000-1000-8000-00805f9b34fb` | 0xFFFF (openScale) | read / write 8 B | – |
| User List (custom) | `00000001-…` | 0xFFFF (openScale) | write 1 B / notifications | **notify** |
| Initials (custom) | `00000002-…` | 0xFFFF (openScale) | write 3 B (SBF73 only) | – |
| Activity Level (custom) | `00000004-…` | 0xFFFF (openScale) | write 1 B | – |
| Take Measurement (custom) | `00000006-…` | 0xFFFF (openScale) | write 1 B / notifications | **notify** |
| Refer Weight BF (custom) | `0000000b-…` | 0xFFFF (openScale) | read | – |
| Battery Level | 0x2A19 | 0x180F | read only | – |
| HW / FW / SW revision | 0x2A27 / 0x2A26 / 0x2A28 | 0x180A | read | – |

UUID constants: `SS:35-40` (custom SBF72 set), 0x0003 Target Weight exists only for "BF105" and is
**not** used for SBF72/73 (CONFIRMED, never mapped in `BLA:1891-1937`).

### 2.1 CCCD enable order — CONFIRMED (`BLA:3058-3120`)

Order of `bluetoothGattCharacteristicDescriptor`:

1. Current Time 0x2A2B → notify `01 00`
2. User List 0x0001 → notify `01 00`
3. User Control Point 0x2A9F → indicate `02 00`
4. Weight Measurement 0x2A9D → indicate `02 00`
5. Database Change Increment 0x2A99 → notify `01 00`
6. Body Composition Measurement 0x2A9C → indicate `02 00`
7. Take Measurement 0x0006 → notify `01 00`

Each write is posted **1000 ms** after the previous `onDescriptorWrite` (the first one 1000 ms after
the start) (`BLA:3077-3101`). If `writeDescriptor` cannot be started, it retries once more
(counter 2), then calls `BackgroundDisconnect()`. INFERRED from this: all 7 characteristics exist on
the scale and all have a CCCD (a missing CCCD would throw and end in a disconnect), including
Current Time (notify) and the custom User List / Take Measurement (notify).

After the 7th `onDescriptorWrite`, the app writes the current time (`BLA:1185-1188`).

---

## 3. Connection sequence

### 3.0 Bonding — CONFIRMED (`BLA:1940-1960`, `BLA:1368-1386`)

After `discoverServices()` succeeds:
- bond state `BOND_BONDED` (12) → `deviceBondedSuccessfully()` then CCCD sequence;
- `BOND_NONE` (10) → `device.createBond()`, wait for `BOND_STATE_CHANGED` = bonded, then
  `discoverServices()` again, then the CCCD sequence;
- `BOND_BONDING` (11) → nothing (waits).

SBF72/SBF73 are in `pairingKeySupportDeviceList` (`BleConstants.java:115-118`): when the bond falls
back to NONE the app shows "Enter the correct code. Check whether you have entered the correct code or
whether you need to enter the code in the notification bar." (`BleUtilities.java:382-391`,
`ActivityWrongPasskeyDialog.java`, strings `lbl_passkey_*`). **INFERRED: the scale uses LE Secure
pairing with a passkey shown on the scale display, typed by the user in the OS pairing dialog.**

### 3.1 Current Time write (0x2A2B) — CONFIRMED (`BLA:3014-3040`)

10 bytes, phone local time: `year(u16) month day hour minute second dayOfWeek fractions256=0 adjust=0`.
Day of week: `Calendar.DAY_OF_WEEK - 1`, 0 replaced by 7 → **1 = Monday … 7 = Sunday**.

Example 2026-10-17 08:30:15 (Saturday): `EA 07 0A 11 08 1E 0F 06 00 00`

On write success, `scaleAfterWriteTime` → after `timeOutMills` = **200 ms** (`BLA:1366`; 1500 ms only if
the service object is null) → read user list (`BA:2957-2973`).

### 3.2 Custom User List (0x0001) — CONFIRMED

Request: write `00` (`BLA:3284-3296`, the app clears its buffer first, `BLA:3276-3282`).

Response: a series of notifications on 0x0001 (`BLA:658-681`), dispatched on `value[0]`:

| value[0] | meaning (app behaviour) |
|---|---|
| `0x00` | one user record; appended to a list |
| `0x01` | end of list, success (`BA:3026` / `3044`) |
| `0x02` | failure / no user. If records were already received, the app re-requests the list up to 2 times (`BA:3027-3040`); openScale labels it "no user on scale" |
| `0x11` | answer to "display PIN": PIN shown (`ShowConsentCodeStatus(true)`) (`BA:3066-3071`) |
| `0x12` | answer to "display PIN": failed (`ShowConsentCodeStatus(false)`) |
| other | treated as end-of-list with that status code |

User record (`BA:4706-4723`, `UI/SBF7xCreateNewUserScreen.java:1672-1731`), only used if length > 8:

| offset | size | field |
|---|---|---|
| 0 | 1 | `0x00` |
| 1 | 1 | user index (1..8) |
| 2 | 3 | initials, ASCII; `FF FF FF` = none |
| 5 | 2 | birth year |
| 7 | 1 | birth month (1-12) |
| 8 | 1 | birth day |
| 9 | 1 | height, cm (uint8) |
| 10 | 1 | gender, 0 = male, 1 = female |
| 11 | 1 | activity level 1..5 |

Example (P01 "ABC", 1990-01-01, 175 cm, male, level 3):
`00 01 41 42 43 C6 07 01 01 AF 00 03`, then end `01`.

The app user is "found" if its stored `userIndex` is among the record indices (`BA:3044-3058`).

### 3.3 "Display PIN" trick for an existing user — CONFIRMED (`BLA:2249-2267`)

Write `0x10 + userIndex` (1 byte) to 0x0001, e.g. user 1 → `11`, user 3 → `13`.
The scale shows a 4-digit PIN ("A 4-digit PIN code will now be shown on the scale display",
string `SBF72_scale_pinEntryInfo2`). The user types it; the app then sends a UCP Consent with that
index and PIN (`UI/SBF7xDeviceEnterPINExistingUserActivity.java:395, 603, 837-862`, `BA:3997-4005`).
The same trick is used after a wrong stored PIN (`TabbedActivity.java:1610-1681`).

INFERRED caveat: the reply is `0x11` (ok) or `0x12` (fail) whatever the index; the app maps only
`0x11` to success. openScale assumes the reply is always `0x11`.

### 3.4 User Control Point (0x2A9F) — CONFIRMED

| op | request | built at |
|---|---|---|
| Register New User | `01 <consent u16>` | `BLA:3001-3012` |
| Consent | `02 <index u8> <consent u16>` | `BLA:2892-2904` |
| Delete User Data (current consented user) | `03` | `BLA:3176-3187` |
| List All Users (0x04) | **never sent** by the app | – |

Responses are indications `20 <req op> <result> [param]` (`BLA:683-767`):

- `20 01 01 <idx>`: registered, new user index `idx` (`BLA:690-714`).
- `20 02 01`: consent OK. `20 02 05`: user not authorized (wrong PIN / index).
- `20 03 xx`: delete answered (the app does not check `xx`, `BLA:760-765`).
- Register failures (e.g. result `0x04` "operation failed" when the 8 slots are full, INFERRED from the
  UDS spec and openScale) are **silently ignored** by the app: only result 1 is handled.

Consent code (PIN): `BA:4641-4648` → `(int)(Math.random() * 9000) + 1000`, i.e. **1000..9999**,
generated by the app, sent in Register, stored in the app DB with the user index
(`BA:3129-3147`, `BA:4445-4446`, `BA:4482-4483`).

Examples: register with PIN 4321 (0x10E1) → `01 E1 10`; reply `20 01 01 03`;
consent → `02 03 E1 10`; reply `20 02 01`; bad PIN → `20 02 05`; delete → `03`, reply `20 03 01`.

#### New-user registration, as the app sequences it — CONFIRMED

1. `createUser(pin)` → 200 ms → `01 pinL pinH` (`BLA:3392-3397`, `2976-2991`).
2. `20 01 01 idx` → 2000 ms → `02 idx pinL pinH` (`BLA:2907-2919`).
3. `20 02 05` → `checkAndReAttempt` (`BLA:2954-2974`): resend consent, each retry armed with a
   200 ms timer, up to 5; then one fresh Register; if that gives a different index the app gives up
   (`isNeedToResetScale`, empty in `BA:254`).
4. `20 02 01` → `createUserResponse(idx, pin)` → UI writes the user data (section 4) with
   Database Change Increment = 1 (`UI/SBF7xUserSettings.java:1341`).
5. After the last write the UI opens `SBF7xUserAssignment`, which **700 ms later writes Take
   Measurement** (`UI/SBF7xUserAssignment.java:146-161`); the user steps on the scale for the
   initial ("reference") measurement.

#### Existing user on the scale — CONFIRMED

User list → pick a record → `1x` (show PIN) → user types PIN → `02 idx pin` → on `20 02 01`
(`BA:3207-3224`): read 0x2A99; the user data from the user list record is compared with the app
profile, and on mismatch the app asks "change data in the HealthCoach / change data in the scale"
(`BA:4007-4047`, `BA:4961-5047`). Then Take Measurement as above.

### 3.5 Database Change Increment (0x2A99) — CONFIRMED

- Read (`BLA:1048-1060`): `u32`; `value[0] == 0xFF` → "unset" (−2).
- Write (`BLA:3366-3377`): `u32`. App value: 1 when the user is created (`UI/SBF7xUserSettings.java:1341`,
  `BA:4009/4049`), +1 at each profile edit (`com/impirion/user/ProfileUpdateScreen.java:1760`).
- On every sync after a successful consent, the SBF73 path reads it and compares with the stored
  value (`BA:3223`, `BA:4276-4283`, `BA:4967`). Equal → OK; different → mismatch dialog.
- Notifications on 0x2A99 are enabled but ignored.
- Example: `01 00 00 00`.

### 3.6 Custom Activity Level (0x0004) — CONFIRMED

1 byte, **1..5** (seekbar max 4, value = progress + 1, `UI/SBF7xUserSettings.java:274, 829, 1341`).
PAL used by the app: 1 → 1.15; 2 → 1.40 (m) / 1.35 (f); 3 → 1.50 / 1.45; 4 → 1.85 / 1.70; 5 → 2.10 / 2.00
(`com/beurer/connect/healthmanager/core/util/Utilities.java:500-522`). Example level 3: `03`.

### 3.7 Custom Initials (0x0002) — CONFIRMED, SBF73 only

Exactly 3 bytes, ASCII, padded with `0x20` (`BLA:3343-3364`). The UI keeps only `[A-Za-z0-9]`, upper-cases
and trims (`UI/SBF7xUserSettings.java:1429-1432, 1316-1336`). Example "FC" → `46 43 20`.
Note: if the string is empty the 3 bytes stay `00 00 00` (`BLA:3347-3357`).

### 3.8 Custom Scale Setting (0x0000) — CONFIRMED layout, partly INFERRED meaning

Read (`BLA:1108-1117`, parse `BA:3074-3126`):

| offset | field |
|---|---|
| 0 | unknown |
| 1 | unit: **0 = kg, 1 = lb, 2 = st** (`UI/SBF7xUnitAndUserAllocationLimitScreen.java:431-445`) |
| 2-3 | unknown |
| 4-5 | user detection limit ×10 kg (u16): 20 / 30 / 40 = "Sensitive (2kg)" / "Normal (3kg)" / "Permissive (4kg)" (`…LimitScreen.java:493-508`) |
| 6-7 | "Bf" value ×10 (u16), stored per user |

Write (`BLA:3457-3468`, called from `BA:4877-4940` only when the unit changed):
`FF <unit> FF FF <limit×10 u16> <bf u16>`. INFERRED: `FF` = "leave unchanged"; `writeScaleSetting`
receives language and time format arguments but never encodes them, which suggests bytes 0/2/3 are
those settings. Note the app writes `bf` without the ×10 it divides by when reading (likely a bug).
Example kg, normal: `FF 00 FF FF 1E 00 00 00`.

Note: this unit enum (0/1/2) differs from `BleConstants.SCALE_UNIT_*` (1/2/4), which is for SBF70.

### 3.9 Custom Refer Weight BF (0x000B) — CONFIRMED read only

Read after Scale Setting in "read all info" (`BLA:1116`). Parsed as `u16 × 0.005 kg` at offset 0 and
discarded (`BA:4942-4944`).

### 3.10 Custom Take Measurement (0x0006) — CONFIRMED

Write `00` (`BLA:3399-3415`). Answer: notification, 1 byte (`BLA:769-777`, `BA:4825-4848`):

| value | app behaviour |
|---|---|
| `01` | OK, wait for the measurement |
| `02`, `03` | "Sorry, it was not possible to complete your initial measurement" + Restart button (re-sends `00`) (`UI/SBF7xUserAssignment.java:225-229, 351-358`) |
| `04` | not authorized → re-send Consent with stored index/PIN (`BA:4834-4846`) |
| `11` (17) | "unknown measurement" event |

The app sends Take Measurement only during pairing/user assignment, **not** during background syncs.

### 3.11 Background sync (already paired user) — CONFIRMED (`TabbedActivity.java:1452-1497`)

connect → (bond) → 7 CCCDs (1 s apart) → Current Time → 200 ms → user list `00` → if the app's user
index is in the list: 100 ms → Consent `02 idx pin` → `20 02 01` → read 0x2A99 and compare →
`CheckAssignUserStatus(true)` → `readScaleAllInfo` chain: read 0x0000 → 0x000B → 0x2A27 → 0x2A19 →
0x2A26 → 0x2A28 (each read issued from the previous read callback, `BLA:1108-1159`).
Measurements arrive as indications (section 5) whenever the scale sends them.
If the user index is not in the list → "Your user profile could not be found…" (re-create or remove).
If Consent returns 5 → show PIN on scale (`1x`) and ask the user for the PIN.

---

## 4. User Data writes — CONFIRMED (`BLA:917-994`, `BLA:3222-3341`)

Chained, each one 50 ms after the previous write's success callback:

1. Date of Birth 0x2A85: `year(u16) month day` (`BLA:3260-3274`); app DOB string parsed with
   `yyyy-MM-dd'T'HH:mm:ss.SSS`. Example 1990-01-01 → `C6 07 01 01`.
2. Gender 0x2A8C: 1 byte, **0 = male, 1 = female** (app value 2 = female → 1, `BLA:935`).
3. Height 0x2A8E: **1 byte, cm** (`BLA:3317-3328`; the read parser also takes 1 byte, `BLA:1081-1087`).
   Example 180 cm → `B4`.
4. Activity Level 0x0004: 1 byte 1..5.
5. SBF73: Initials 0x0002 (3 bytes) → then Database Change Increment 0x2A99 (u32) → done
   (`writeInitialsSuccessfully`). SBF72: stops after activity level (no initials, no DB increment).

If a write is requested while the "primary process" (CCCD + info reads) is still running, it is
deferred until the Software Revision read completes (`BLA:3231-3257`, `BLA:1152-1155`).
No age, first name, weight or other UDS characteristics are written.

---

## 5. Measurements

### 5.1 Packets and correlation — CONFIRMED (`BLA:779-805`, `BA:4781-4823`)

- Weight Measurement indication → new package `{weight, receivedAt=now}`; delivered to the app at once.
- Body Composition indication → attached to the **last** weight package; delivered again.
- `insertMeasurement` stores a package **only if both weight and body composition are present**
  (`BA:4786`). A weight without a following BC packet is dropped.
- Store dedupe: same user + date + time + kg + lb → not inserted again (`GDH` `insertScaleMeasurementRecord`,
  `checkForDuplicateByUserId`). INFERRED: the scale may re-send stored measurements on later connections.
- The user index inside the packet is **not checked**; packets are assigned to the consented user.
- After a successful Consent the app flushes any buffered packages (`BLA:719-721`).
- No RACP / history request exists for the scale. INFERRED (WSS/UDS spec + openScale): the scale
  sends the stored measurements of the consented user after Consent, and a live measurement after
  Take Measurement or when the user steps on while connected.
- Weight Scale Feature (0x2A9E) and Body Composition Feature (0x2A9B) are never read; the parser uses
  fixed offsets. Multi-packet BC is not supported.

### 5.2 Weight Measurement (0x2A9D) — fixed offsets, CONFIRMED (`GDH:2403-2421`)

| offset | size | field | scale |
|---|---|---|---|
| 0 | 1 | flags (read, not used) | INFERRED value `0x0E` = timestamp + user + BMI/height, SI |
| 1 | 2 | weight | × 0.005 kg (always, the unit flag is ignored) |
| 3 | 7 | timestamp `year(u16) month day hour min sec` | local time; if year < 2000 the app uses "now" (`GDH:2450-2452`) |
| 10 | 1 | user index | not used for routing |
| 11 | 2 | BMI | × 0.1 |
| 13 | 2 | height | × 0.1 → cm (i.e. raw in mm = 0.001 m per spec); not stored |

Example 80.25 kg, 2026-10-17 07:45:00, user 1, BMI 24.8, 1.800 m:
`0E B2 3E EA 07 0A 11 07 2D 00 01 F8 00 08 07`

### 5.3 Body Composition Measurement (0x2A9C) — fixed offsets, CONFIRMED (`GDH:2422-2436`)

| offset | size | field | scale |
|---|---|---|---|
| 0 | 2 | flags (not used) | INFERRED `0x0398` = BMR, muscle %, soft lean mass, body water mass, impedance; no timestamp/user/weight/height |
| 2 | 2 | body fat | × 0.1 % |
| 4 | 2 | BMR | kJ; kcal = round(kJ / 4.1868), only logged |
| 6 | 2 | muscle | × 0.1 % |
| 8 | 2 | soft lean mass | × 0.005 kg |
| 10 | 2 | body water mass | × 0.005 kg |
| 12 | 2 | impedance | × 0.1 Ω, stored as int Ω |

Example fat 22.5 %, BMR 7300 kJ, muscle 38.2 %, SLM 58.5 kg, water 45.0 kg, 520.0 Ω:
`98 03 E1 00 84 1C 7E 01 B4 2D 28 23 50 14`

### 5.4 Metrics: from the scale vs computed by the app — CONFIRMED (`GDH:2437-2498`, `Utilities.java:496-544`)

| metric | source |
|---|---|
| weight, BMI, body fat %, muscle %, impedance | scale |
| water % | app: `body_water_mass / weight × 100` |
| bone mass | app: `weight − weight × fat% / 100 − soft_lean_mass` (only if fat% > 0) |
| BMR (stored) | app, Mifflin-St Jeor with the **app profile**: male `10·w + 6.25·h_cm − 5·age + 5`, female `… − 161`; the scale's BMR is ignored |
| AMR | app: `int(BMR × PAL(activity, gender))` (table in 3.6) |
| visceral fat, muscle mass, fat-free mass | not present / not used |

Worked example (5.2 + 5.3): fat mass 18.06 kg, bone = 80.25 − 18.06 − 58.50 = 3.69 kg,
water = 45.0 / 80.25 = 56.1 %.

---

## 6. Disconnect, battery, timing, error codes

- Disconnect: for SBF72/73 `forceDisconnect()` = `gatt.disconnect(); gatt.close()`, **no command**
  (`BLA:2112-2119`, `BLA:1774-1805`). (The `E7 …` force-disconnect bytes on 0xFFE1 are for SBF70.)
  Remote disconnects with status 19 or 22 are treated as a normal end (`BLA:409-421`).
- Battery: read 0x2A19 once in the "read all info" chain, 1 byte % (`BLA:1134-1138`); no notifications.
- Delays the app inserts:

  | step | delay |
  |---|---|
  | before each CCCD write | 1000 ms (2 attempts each) |
  | Current Time write success → user list request | 200 ms |
  | before Consent (sync / PIN) | 100 ms (`BA:3997-4005`) |
  | before Register | 200 ms |
  | Register OK → Consent | 2000 ms |
  | consent "not authorized" retry timer | 200 ms × 5 |
  | between user data writes | 50 ms |
  | open user assignment → Take Measurement | 700 ms |
  | bonded → UI event | 1500 ms |
  | delete user → local removal fallback | 2500 ms (`BA:4127-4137`) |
  | GATT 133 reconnect | up to 4 tries |

- Codes: UCP result 1 = success, 5 = user not authorized (handled); others (2 op not supported,
  3 invalid parameter, 4 operation failed) = UDS spec, INFERRED, not handled by the app.
  User list status 1/2/0x11/0x12 and Take Measurement 1/2/3/4/0x11: see 3.2 and 3.10.
- Max users: **8** (`Healthcoach.db_upgrade_15-16.sql`, `UI/SBF7xCreateNewUserScreen.java:1765`
  "There is not enough space in the device memory for a new user").
- Delete user (`BA:4946-4959`, `BLA:3470-3473`): Consent `02 idx pin`, then on *any* `20 02 xx`
  the app writes `03`; `20 03 xx` → done.

---

## 7. SBF73-specific behaviour, and app vs openScale

SBF73 vs SBF72 inside the app (CONFIRMED):
- SBF73 writes Initials (0x0002) and then Database Change Increment; SBF72 writes neither
  ("Initials are not supported by SBF72", `BLA:959-970`, `BLA:986-990`).
- SBF73 checks the Database Change Increment after every consent (`BA:3207-3224`, `BA:4961`).
- SBF73 has its own pairing selection screen (1.5). Same GATT, same packets otherwise.

App vs openScale (`SanitasSbf72Handler.kt`, `StandardWeightProfileHandler.kt`):

| topic | official app | openScale |
|---|---|---|
| name match | exact `SBF73` | substring `sbf73` / `sbf72` / `bf915`, case-insensitive |
| adv status byte 0xA5xx | parsed (pairing bit, measurement flags) | ignored |
| bonding | explicit `createBond()` before anything, passkey | implicit (BLESSED) |
| CCCDs | 7, fixed order, 1 s apart, incl. Current Time + Take Measurement notify | WM, BCM, DBInc, UCP, **Battery notify**, User List |
| time write | after all CCCDs, its success triggers the user list | immediately |
| user list | requested on every connection | only when no stored consent |
| UCP List All Users (0x04) | never | sent by the base handler when there is no mapping (`super.onConnected`) |
| PIN range | 1000..9999 | 0..9999 |
| Register → Consent | 2 s wait, 5 retries on "not authorized" | immediate |
| user data order | DOB, gender, height, activity, initials, DBInc (50 ms after each ack) | activity, initials, DOB, gender, height, DBInc |
| height | **1 byte** | 2 bytes |
| initials | 3 bytes, space padded | 1-3 bytes, not padded |
| DB change increment | 1 at creation, +1 per profile edit, compared at each sync | always writes 1 |
| take measurement | only at pairing / user assignment | after **every** successful consent |
| parsing | fixed offsets, flags ignored, unit flag ignored | flag-driven, lb resolution supported |
| weight without BC | dropped | published |
| BMR | Mifflin from app profile | scale BMR only logged |
| scale settings, refer weight, delete user | supported | not implemented |

---

## 8. Implementation checklist (Python, bleak via HA bluetooth)

Persist per scale: MAC, user index, PIN (consent code), DB change increment, last measurement timestamp.

### 8.1 First-time registration (new user on the scale)

1. Scan for local name exactly `SBF73` (the app also requires a non-empty service UUID list; the real scale
   advertises `0x181D`, appearance `0x0C80`, manufacturer data `0x0613: 01 00`). Do not require a
   `0xA5nn` UUID: the real idle scale does not send one (1.4). CONFIRMED (app), OBSERVED (scale).
2. Connect (`autoConnect=False`), discover services. CONFIRMED.
3. Pair/bond (`await client.pair()`); expect a passkey shown on the scale. INFERRED: needs a BlueZ agent
   that can enter a passkey (KeyboardOnly/KeyboardDisplay); may not work through ESPHome proxies.
4. Enable, in this order, ~1 s apart (shorter is probably fine, INFERRED): notify 0x2A2B, notify 0x0001,
   indicate 0x2A9F, indicate 0x2A9D, notify 0x2A99, indicate 0x2A9C, notify 0x0006. CONFIRMED order.
5. Write Current Time (10 B, local time, 1 = Monday). CONFIRMED.
6. ~200 ms later write `00` to 0x0001; collect `00…` records until status `01` (or `02`). Abort if
   there are 8 records. CONFIRMED.
7. PIN = random 1000..9999. Write `01 pinL pinH` to 0x2A9F; wait `20 01 01 idx`. No answer or a
   result ≠ 1 → fail (INFERRED: `04` = full).
8. Wait ~2 s, write `02 idx pinL pinH`; expect `20 02 01` (retry up to 5× on `20 02 05`). CONFIRMED.
9. With ~50 ms between acknowledged writes: DOB `yyL yyH mm dd` → gender `00|01` → height 1 byte cm →
   activity `01..05` to 0x0004 → initials 3 B to 0x0002 → DB change increment `01 00 00 00`. CONFIRMED.
10. Optional: read 0x0000 and write `FF unit FF FF limit×10 bf` to set kg/lb/st and the detection limit.
11. Write `00` to 0x0006; expect notify `01` (`02`/`03` → ask to retry, `04` → re-consent). Ask the user to
    step on the scale. CONFIRMED.
12. Receive 0x2A9D then 0x2A9C indications; pair them (BC goes with the previous weight); parse with the
    offsets of 5.2/5.3 (better: parse by flags and check they match `0x0E` / `0x0398`).
13. Disconnect (just close; no command). CONFIRMED.

### 8.1b Linking to an existing user on the scale

After step 6: write `0x10 + idx` to 0x0001, expect notify `11`, ask the user for the 4-digit PIN shown on
the scale, then step 8 with that PIN. Optionally compare the user list record with the HA profile and
rewrite step 9 data. CONFIRMED.

### 8.2 Subsequent automatic syncs

1. Passive scan for the stored MAC. The app connects to *any* advertisement of the trusted scale while it is
   in the foreground, with no cool-down (1.4, CONFIRMED). The scale advertises continuously (OBSERVED), so HA
   must throttle: connect when the manufacturer data or UUID list changes, otherwise at most every
   15-30 min, plus a manual "sync now". INFERRED.
2. Connect; the bond is reused (no passkey). CONFIRMED (app expects `BOND_BONDED`).
3. Same CCCD sequence (step 4) and Current Time write (step 5). CONFIRMED.
4. Optional, like the app: user list `00` and check that the stored index is present; if absent the user
   was deleted on the scale → re-register. CONFIRMED app behaviour.
5. Consent `02 idx pinL pinH`. `20 02 05` → PIN invalid → ask the user (show-PIN trick `1x`). CONFIRMED.
6. Optional: read 0x2A99 and compare with the stored increment (profile changed on the scale or another
   phone). CONFIRMED app behaviour.
7. Collect 0x2A9D / 0x2A9C indications for a few seconds after consent (stored history, INFERRED), dedupe by
   timestamp + weight (the app does). Do **not** send Take Measurement unless you want a live measurement.
8. Read battery 0x2A19 (and optionally 0x0000, 0x000B, 0x2A26-0x2A28). CONFIRMED.
9. Disconnect. CONFIRMED.

Derived metrics to publish: water % = water mass / weight; bone = weight − fat mass − soft lean mass;
BMR either from the scale (kJ / 4.1868) or Mifflin like the app.

## 8.3 Behaviour observed on a real SBF73 (2026-10-17) — OBSERVED

- **Wake-up signal.** Idle, the scale advertises every few seconds with an empty Service Data AD
  for 0x181D (`03 16 1D 18`). Woken up by a weighing, it advertises every ~200 ms and the service
  data becomes `01` (`04 16 1D 18 01`). Manufacturer data (`0x0613: 01 00`) never changes. This is
  the trigger to connect. Home Assistant's `async_register_callback` does not fire on unchanged
  advertisements, so use `async_register_advertisement_callback`.
- **Idle scale refuses GATT writes.** CCCD writes fail with ATT error 0x0E (Unlikely Error) when
  nobody is on the scale. Connect only while it is awake.
- **Pending measurement comes with the consent.** Order seen: user list `00` → records + `01` →
  Consent written → Weight Measurement + Body Composition indications (~350 ms later) → UCP
  response `20 02 01`. A weighing with socks gives a Body Composition packet with all values at 0.
- **Repeat loop.** After one full weighing (with body composition) the scale re-sent the same
  weight + body composition pair every ~270 ms for 49 s, and only then answered the consent.
  Deduplicate measurements and wait up to ~70 s for the consent answer.
- **Measurements are delivered once.** A measurement already delivered to a connection is not
  sent again on the next consent.
- **BlueZ auto-connect.** Each `Device1.Connect` turns auto-connect on for the bonded scale and
  only `Device1.Disconnect` turns it off (untrusted device). If the scale drops the link first,
  BlueZ reconnects it at its next wake-up, receives the measurement and acknowledges it with no
  client listening: the measurement is lost. Always call `Device1.Disconnect` after a session.
- **One client only.** The scale takes a single connection and stops advertising while connected.
  Two clients polling it (e.g. ble-scale-sync and this integration) steal each other's measurements.

## 9. Open questions

1. Bonding: passkey entry is inferred from the "enter the correct code" alert; Just Works vs passkey and the
   passkey length are not visible in the code. This decides whether an ESPHome proxy can be used.
2. Service UUID of the custom characteristics (`0xFFFF` per openScale) is not referenced by the app.
3. Whether the scale sends all stored measurements after every consent, or only unsent ones, and whether
   it needs the Current Time write first.
4. Unit flag: the app always uses 0.005 kg; behaviour when the scale is set to lb/st is unknown.
5. Height as 1 byte (app) vs 2 bytes (openScale): both appear to work, the app's form is the reference.
6. Exact meaning of Scale Setting bytes 0, 2, 3 and of Take Measurement codes 2/3, user list 0x12.
7. Whether the CCCD on Current Time / Take Measurement must be enabled for the scale to answer.
8. Meaning of the manufacturer data (company `0x0613`, observed `01 00` when idle): the app never reads it.
   Log it in HA before and after a measurement, during pairing, and with users added, to find a
   "measurement pending" flag.
9. Whether the scale ever advertises the `0xA5nn` status UUID the app looks for (maybe only in pairing
   mode or on another firmware); the observed idle advertisement does not contain it.
